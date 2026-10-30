"""Agent 2: Normalizer & Identity Resolver for IdentityShield v3.

Follows context.md Section 5, 8, 10, 13 and PRD §8, §12:
- Subscribes: events
- Publishes: events.normalized, deadletter
- Normalizes Okta and CloudTrail fields to the canonical Event model
- Classifies eventClass, actionType, readOnly, uncatalogued via catalog.py
- Identity resolution rules IR-1..IR-6 with confidence scoring:
  - 1.0 for direct match (Okta actor, explicit alias)
  - 0.9 for SAML role session name / federated link
  - 0.8 for key lineage / assumed-role credentials
  - 0.5 for unresolved principals
- Removes attrs['_raw'] before publishing events.normalized
- Persists identities_v3 and identity_aliases_v3 in batches
"""
import copy
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

from app.v3 import catalog, store
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    DeadletterPayload,
    Event,
    Message,
    Source,
)

log = logging.getLogger(__name__)


def parse_okta_fields(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract and normalize all relevant Okta fields (PRD §8.1)."""
    client = raw.get("client") or {}
    ua_obj = client.get("userAgent") or {}
    user_agent = ua_obj.get("rawUserAgent") if isinstance(ua_obj, dict) else str(ua_obj)
    if not user_agent:
        user_agent = "unknown"

    actor = raw.get("actor") or {}
    raw_principal = actor.get("alternateId") or actor.get("id") or "unknown"

    auth_ctx = raw.get("authenticationContext") or {}
    external_session_id = auth_ctx.get("externalSessionId")

    outcome_obj = raw.get("outcome") or {}
    res = outcome_obj.get("result", "unknown").lower()
    if res in ("success", "successful"):
        outcome = "success"
    elif res in ("failure", "fail", "failed"):
        outcome = "failure"
    elif res in ("deny", "denied"):
        outcome = "deny"
    else:
        outcome = res

    # Target info
    target_list = raw.get("target") or []
    target_user = None
    resource_arn = None
    for t in target_list:
        if isinstance(t, dict):
            if t.get("type") in ("User", "AppUser"):
                target_user = t.get("alternateId") or t.get("displayName")
            elif not resource_arn and t.get("id"):
                resource_arn = str(t.get("id"))

    mfa_result = None
    event_type = raw.get("eventType", "")
    if "mfa" in event_type.lower() or "verify" in event_type.lower():
        mfa_result = outcome_obj.get("result")

    return {
        "event_id": str(raw.get("uuid") or raw.get("eventId") or ""),
        "time": str(raw.get("published") or raw.get("eventTime") or ""),
        "source": Source.okta,
        "action": str(event_type),
        "raw_principal": str(raw_principal),
        "user_name": str(actor.get("alternateId") or ""),
        "actor_id": str(actor.get("id") or ""),
        "session_id": str(external_session_id) if external_session_id else None,
        "src_ip": str(client.get("ipAddress") or "127.0.0.1"),
        "user_agent": str(user_agent),
        "outcome": outcome,
        "resource_arn": resource_arn,
        "region": None,
        "access_key_id": None,
        "vpc_endpoint_id": None,
        "external_session_id": external_session_id,
        "policy_arn": None,
        "role_arn": None,
        "target_user": target_user,
        "mfa_result": mfa_result,
        "okta_session_id": external_session_id,
        "session_issuer_arn": None,
        "source_identity": None,
        "error_code": None,
        "raw": raw,
    }


def parse_cloudtrail_fields(raw: dict[str, Any]) -> dict[str, Any]:
    """Extract and normalize all relevant CloudTrail fields (PRD §8.2)."""
    user_identity = raw.get("userIdentity") or {}
    principal_arn = user_identity.get("arn")
    user_name = user_identity.get("userName")
    principal_id = user_identity.get("principalId")
    identity_type = user_identity.get("type", "unknown")

    raw_principal = principal_arn or user_name or principal_id or identity_type
    access_key_id = user_identity.get("accessKeyId")
    source_identity = user_identity.get("sourceIdentity")

    session_ctx = user_identity.get("sessionContext") or {}
    session_issuer = session_ctx.get("sessionIssuer") or {}
    session_issuer_arn = session_issuer.get("arn")

    req_params = raw.get("requestParameters") or {}

    role_session_name = req_params.get("roleSessionName")
    role_arn = req_params.get("roleArn")
    policy_arn = req_params.get("policyArn")
    target_user = req_params.get("userName")

    # Resource ARN from resources list
    resource_arn = None
    resources = raw.get("resources") or []
    if isinstance(resources, list) and resources:
        first_r = resources[0]
        if isinstance(first_r, dict):
            resource_arn = first_r.get("ARN") or first_r.get("arn")

    # Outcome
    error_code = raw.get("errorCode")
    if error_code:
        outcome = "deny" if "denied" in error_code.lower() or "unauthorized" in error_code.lower() else "failure"
    else:
        outcome = "success"

    # Session ID
    session_id = None
    if identity_type == "AssumedRole" and principal_arn and "/" in principal_arn:
        # e.g. arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
        session_id = principal_arn.split("/")[-1]

    return {
        "event_id": str(raw.get("eventID") or raw.get("eventId") or ""),
        "time": str(raw.get("eventTime") or raw.get("published") or ""),
        "source": Source.cloudtrail,
        "action": str(raw.get("eventName") or "unknown"),
        "raw_principal": str(raw_principal),
        "user_name": str(user_name or ""),
        "principal_id": str(principal_id or ""),
        "identity_type": str(identity_type),
        "session_id": session_id,
        "src_ip": str(raw.get("sourceIPAddress") or "127.0.0.1"),
        "user_agent": str(raw.get("userAgent") or "unknown"),
        "outcome": outcome,
        "resource_arn": resource_arn,
        "region": raw.get("awsRegion"),
        "access_key_id": access_key_id,
        "vpc_endpoint_id": raw.get("vpcEndpointId"),
        "external_session_id": raw.get("external_session_id"),
        "role_session_name": role_session_name,
        "policy_arn": policy_arn,
        "role_arn": role_arn,
        "target_user": target_user,
        "created_access_key": (raw.get("responseElements") or {}).get("accessKey", {}).get("accessKeyId"),
        "temp_access_key": (raw.get("responseElements") or {}).get("credentials", {}).get("accessKeyId"),
        "mfa_result": None,
        "okta_session_id": None,
        "session_issuer_arn": session_issuer_arn,
        "source_identity": source_identity,
        "error_code": error_code,
        "raw": raw,
    }


def resolve_identity(fields: dict[str, Any], state: dict[str, Any]) -> tuple[str, float]:
    """Identity resolution rules IR-1 to IR-6 (PRD §8.3).

    Returns (canonical_identity_id, resolution_confidence).
    """
    aliases: dict[str, str] = state["aliases"]
    key_lineage: dict[str, dict[str, Any]] = state["key_lineage"]
    source = fields.get("source")
    action = fields.get("action", "")
    raw = fields.get("raw") or {}

    # 1. Okta Source: Direct Identity (1.0)
    if source == Source.okta or source == "okta":
        raw_principal = fields.get("raw_principal") or "unknown"
        user_name = fields.get("user_name") or raw_principal
        actor_id = fields.get("actor_id")

        canonical_id = user_name
        aliases[canonical_id] = canonical_id
        if actor_id:
            aliases[actor_id] = canonical_id
        if raw_principal:
            aliases[raw_principal] = canonical_id

        # Record in identities state
        if canonical_id not in state["identities"]:
            state["identities"][canonical_id] = {
                "primary_user": canonical_id,
                "email": canonical_id if "@" in canonical_id else f"{canonical_id}@corp.example",
            }
            state["pending_db_identities"].append(canonical_id)

        return canonical_id, 1.0

    # 2. CloudTrail: IR-1 / IR-2 AssumeRoleWithSAML or SAML role session
    if action in ("AssumeRoleWithSAML", "AssumeRole"):
        req_params = raw.get("requestParameters") or {}
        role_session = fields.get("role_session_name") or req_params.get("roleSessionName") or fields.get("source_identity")
        resp_elements = raw.get("responseElements") or {}
        creds = resp_elements.get("credentials") or {}
        temp_access_key = creds.get("accessKeyId")

        # Resolve parent from role_session
        matched_identity = None
        conf = 0.9
        if role_session:
            if role_session in aliases:
                matched_identity = aliases[role_session]
            elif "@" in role_session:
                # Direct email match
                matched_identity = role_session
                aliases[role_session] = matched_identity
            else:
                matched_identity = role_session

        if not matched_identity:
            matched_identity = fields.get("raw_principal") or "unresolved"
            conf = 0.5

        # Record temp credentials lineage
        if temp_access_key:
            key_lineage[temp_access_key] = {"creator": matched_identity, "owner": matched_identity}
            aliases[temp_access_key] = matched_identity
            state["pending_db_aliases"].append((temp_access_key, matched_identity, "assumed_temp_key"))

        # Record assumed role ARN in aliases
        assumed_user = resp_elements.get("assumedRoleUser") or {}
        assumed_arn = assumed_user.get("arn")
        if assumed_arn:
            aliases[assumed_arn] = matched_identity
            state["pending_db_aliases"].append((assumed_arn, matched_identity, "assumed_role_arn"))

        return matched_identity, conf

    # 3. CloudTrail: IR-4 CreateAccessKey
    if action == "CreateAccessKey":
        resp_elements = raw.get("responseElements") or {}
        req_params = raw.get("requestParameters") or {}
        ak_obj = resp_elements.get("accessKey") or {}
        new_key_id = ak_obj.get("accessKeyId")
        target_user = req_params.get("userName") or fields.get("target_user")

        # Caller identity
        caller_identity, caller_conf = _resolve_cloudtrail_caller(fields, state)
        owner_identity = aliases.get(target_user, caller_identity) if target_user else caller_identity

        if new_key_id:
            key_lineage[new_key_id] = {
                "creator": caller_identity,
                "owner": owner_identity,
            }
            # The new key maps to owner or creator
            aliases[new_key_id] = caller_identity
            state["pending_db_aliases"].append((new_key_id, caller_identity, "created_access_key"))

        return caller_identity, caller_conf

    # 4. Standard CloudTrail resolution
    return _resolve_cloudtrail_caller(fields, state)


def _resolve_cloudtrail_caller(fields: dict[str, Any], state: dict[str, Any]) -> tuple[str, float]:
    """Helper for resolving CloudTrail caller via lineage, aliases, or principal."""
    aliases: dict[str, str] = state["aliases"]
    key_lineage: dict[str, dict[str, Any]] = state["key_lineage"]
    access_key = fields.get("access_key_id")
    raw_principal = fields.get("raw_principal") or ""
    user_name = fields.get("user_name") or ""

    # Check key lineage first (IR-4, IR-3)
    if access_key and access_key in key_lineage:
        lineage = key_lineage[access_key]
        resolved = aliases.get(access_key) or lineage.get("creator") or lineage.get("owner")
        return resolved, 0.8

    if access_key and access_key in aliases:
        return aliases[access_key], 0.8

    # Check if ARN contains assumed-role session name (e.g. .../Role/alice@example.com)
    if "assumed-role" in raw_principal:
        parts = raw_principal.split("/")
        if len(parts) >= 3:
            session_name = parts[-1]
            if session_name in aliases:
                return aliases[session_name], 0.9
            if "@" in session_name:
                aliases[session_name] = session_name
                return session_name, 0.9

    # Direct match in aliases
    if raw_principal in aliases:
        return aliases[raw_principal], 1.0
    if user_name and user_name in aliases:
        return aliases[user_name], 1.0

    # Unresolved principal (IR-5)
    fallback_id = user_name or raw_principal or "unresolved"
    return fallback_id, 0.5


class Normalizer(Agent):
    """Agent 2: Normalizer and Identity Resolver.

    Maps Okta and CloudTrail fields to the canonical Event model, classifies
    actions via catalog.py, applies identity resolution IR-1..IR-6, strips
    raw attributes, and persists identity records.
    """

    num = 2
    agent_id = "a02"
    name = "Normalizer & Identity Resolver"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["events"]
    publishes: ClassVar[list[str]] = ["events.normalized", "deadletter"]
    path = "hot"

    def init_state(self) -> dict[str, Any]:
        return {
            "aliases": {},
            "key_lineage": {},
            "identities": {},
            "pending_db_identities": [],
            "pending_db_aliases": [],
        }

    def _flush_persistence(self, state: dict[str, Any], ctx: AgentContext) -> None:
        """Batch write discovered identities and aliases to SQLite."""
        pending_ids = state.get("pending_db_identities", [])
        pending_al = state.get("pending_db_aliases", [])

        if not pending_ids and not pending_al:
            return

        now_iso = ctx.clock().isoformat() if callable(ctx.clock) else datetime.now(UTC).isoformat()
        db_path = getattr(ctx.store, "db_path", None) if ctx.store else None

        if pending_ids:
            ident_rows = []
            for ident_id in pending_ids:
                meta = state["identities"].get(ident_id, {})
                ident_rows.append(
                    {
                        "identity_id": ident_id,
                        "primary_user": meta.get("primary_user", ident_id),
                        "email": meta.get("email", ident_id),
                        "department": "Engineering",
                        "privilege_level": 1,
                        "created_at": now_iso,
                        "updated_at": now_iso,
                    }
                )
            try:
                store.insert_many("identities_v3", ident_rows, db_path=db_path)
            except (store.sqlite3.Error, OSError, ValueError):
                log.debug("Store insert for identities_v3 bypassed")
            state["pending_db_identities"] = []

        if pending_al:
            alias_rows = []
            for alias_key, ident_id, a_type in pending_al:
                alias_rows.append(
                    {
                        "alias": alias_key,
                        "identity_id": ident_id,
                        "alias_type": a_type,
                        "created_at": now_iso,
                    }
                )
            try:
                store.insert_many("identity_aliases_v3", alias_rows, db_path=db_path)
            except (store.sqlite3.Error, OSError, ValueError):
                log.debug("Store insert for identity_aliases_v3 bypassed")
            state["pending_db_aliases"] = []

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        if not isinstance(msg.payload, Event):
            dl = DeadletterPayload(
                failed_topic=msg.topic,
                failed_msg_id=msg.msg_id,
                error=f"Expected Event payload, got {type(msg.payload).__name__}",
                producer=self.agent_id,
                raw=getattr(msg.payload, "__dict__", str(msg.payload)),
            )
            return [ctx.new_message(topic="deadletter", payload=dl, producer=self.agent_id)]

        ev: Event = msg.payload
        raw_dict = ev.attrs.get("_raw") or {}

        try:
            if ev.source == Source.okta or "eventType" in raw_dict:
                parsed_fields = parse_okta_fields(raw_dict if raw_dict else ev.attrs)
            else:
                parsed_fields = parse_cloudtrail_fields(raw_dict if raw_dict else ev.attrs)
        except (ValueError, TypeError, KeyError) as exc:
            dl = DeadletterPayload(
                failed_topic=msg.topic,
                failed_msg_id=msg.msg_id,
                error=f"Failed to extract fields: {exc}",
                producer=self.agent_id,
                raw=raw_dict,
            )
            return [ctx.new_message(topic="deadletter", payload=dl, producer=self.agent_id)]

        # 1. Action catalog lookup
        cat_entry = catalog.lookup(ev.source, ev.action)

        # 2. Identity resolution (IR-1 to IR-6)
        identity_id, conf = resolve_identity(parsed_fields, state)

        # 3. Clean and build normalized attrs (remove _raw)
        clean_attrs = copy.deepcopy(ev.attrs)
        clean_attrs.pop("_raw", None)

        # Populate standard attributes
        for k in (
            "access_key_id",
            "vpc_endpoint_id",
            "external_session_id",
            "policy_arn",
            "role_arn",
            "target_user",
            "mfa_result",
            "okta_session_id",
            "session_issuer_arn",
            "source_identity",
            "error_code",
            "created_access_key",
            "temp_access_key",
        ):
            v = parsed_fields.get(k)
            if v is not None:
                clean_attrs[k] = v

        # Read-only flag from CloudTrail raw if present, else from catalog
        is_read_only = bool(raw_dict.get("readOnly", cat_entry.read_only))

        normalized_event = Event(
            event_id=ev.event_id,
            time=ev.time,
            source=ev.source,
            event_class=cat_entry.event_class,
            action=ev.action,
            identity_id=identity_id,
            raw_principal=parsed_fields["raw_principal"],
            session_id=parsed_fields.get("session_id") or ev.session_id,
            src_ip=parsed_fields.get("src_ip") or ev.src_ip,
            user_agent=parsed_fields.get("user_agent") or ev.user_agent,
            outcome=parsed_fields.get("outcome") or ev.outcome,
            resource_arn=parsed_fields.get("resource_arn") or ev.resource_arn,
            read_only=is_read_only,
            region=parsed_fields.get("region") or ev.region,
            late=ev.late,
            uncatalogued=cat_entry.uncatalogued,
            resolution_confidence=conf,
            raw_ref=ev.raw_ref,
            attrs=clean_attrs,
        )

        # Periodic store flush if backlog grows
        if len(state["pending_db_identities"]) >= 50 or len(state["pending_db_aliases"]) >= 50:
            self._flush_persistence(state, ctx)

        out_msg = ctx.new_message(
            topic="events.normalized",
            payload=normalized_event,
            partition_key=identity_id,
            producer=self.agent_id,
        )
        return [out_msg]

    def on_tick(
        self,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Flush pending identity store batches."""
        self._flush_persistence(state, ctx)
        return []
