"""Agent 8: Privilege Escalation Detector.

Recognizes privilege escalation as ordered multi-step paths:
- PE-01: Policy version manipulation (CreatePolicyVersion set as default on self-attached policy).
- PE-02: Admin policy attachment and subsequent privileged call.
- PE-03: Inline policy wildcard and subsequent privileged call.
- PE-04: Lambda PassRole + CreateFunction/UpdateFunctionCode + Invoke.
- PE-05: UpdateAssumeRolePolicy to trust self + AssumeRole.
- PE-06: Add user to admin group + subsequent privileged call.
- PE-07: Create access key or login profile for another user + activity as target user.
- PE-08: Full chain: Discovery burst (>= 5 services in 30 min) -> any PE-01..07 -> data/secrets access.

Warm path, consumes graph.updates, sessions, events.enriched; publishes signals, deadletter.
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

import yaml

from app.v3 import config
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    ActionType,
    EnrichedEvent,
    EventClass,
    Message,
    Signal,
    Stage,
)

log = logging.getLogger(__name__)


def load_privesc_paths(file_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Load privilege escalation path definitions from YAML."""
    if file_path is None:
        file_path = Path(__file__).resolve().parent.parent / "data" / "privesc_paths.yaml"
    p = Path(file_path)
    if not p.is_file():
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict) and "paths" in data:
                return data["paths"]
            return []
    except (yaml.YAMLError, OSError, ValueError):
        log.warning("Could not load privesc paths from %s", p)
        return []


def extract_service_name(event_dict: dict[str, Any]) -> str:
    """Extract standard AWS/Cloud service name from event."""
    action = str(event_dict.get("action", ""))
    if ":" in action:
        return action.split(":", 1)[0].lower()

    attrs = event_dict.get("attrs") or {}
    event_source = str(attrs.get("eventSource") or "")
    if event_source:
        return event_source.replace(".amazonaws.com", "").lower()

    # Heuristic prefix mapping
    lower_action = action.lower()
    if lower_action.startswith(("getsecret", "describesecret")):
        return "secretsmanager"
    if lower_action.startswith(("listbucket", "getobject", "putobject")):
        return "s3"
    if lower_action.startswith(("listuser", "getuser", "listrole", "getrole", "attach", "putuserpolicy", "createpolicy")):
        return "iam"
    if lower_action.startswith(("describeinstance", "describesecuritygroup", "describevpc")):
        return "ec2"
    if lower_action.startswith(("describedb", "listdb")):
        return "rds"
    if lower_action.startswith(("listfunction", "getfunction", "invok")):
        return "lambda"
    if lower_action.startswith("getcalleridentity"):
        return "sts"
    return "other"


def matches_step_predicate(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    step_def: dict[str, Any],
    matched_history: list[dict[str, Any]],
) -> bool:
    """Check if the current event satisfies the predicate for a specific step."""
    action = str(event_dict.get("action", ""))
    action_lower = action.lower()
    attrs = event_dict.get("attrs") or {}
    conditions = step_def.get("conditions") or {}

    expected_actions = step_def.get("actions") or []
    if "action" in step_def:
        expected_actions.append(step_def["action"])

    if expected_actions:
        expected_lower = [a.lower() for a in expected_actions]
        if not any(exp in action_lower for exp in expected_lower):
            return False

    # Check parameter conditions
    if conditions.get("set_as_default"):
        # CreatePolicyVersion setAsDefault
        set_default = (
            attrs.get("setAsDefault")
            or attrs.get("set_as_default")
            or attrs.get("requestParameters", {}).get("setAsDefault")
        )
        if set_default is None:
            # Default in AWS if not specified or True
            return True
        if str(set_default).lower() not in ("true", "1"):
            return False

    if "policy_arn_contains" in conditions:
        policy_arn = str(
            attrs.get("policyArn")
            or attrs.get("policy_arn")
            or attrs.get("requestParameters", {}).get("policyArn")
            or ""
        ).lower()
        targets = [t.lower() for t in conditions["policy_arn_contains"]]
        if not any(t in policy_arn for t in targets):
            return False

    if conditions.get("wildcard_action"):
        # PutUserPolicy / PutRolePolicy policy document has "*"
        doc = str(
            attrs.get("policyDocument")
            or attrs.get("policy_document")
            or attrs.get("requestParameters", {}).get("policyDocument")
            or ""
        )
        if '"*"' not in doc and "'*'" not in doc and ":*" not in doc:
            return False

    if "group_name_contains" in conditions:
        group_name = str(
            attrs.get("groupName")
            or attrs.get("group_name")
            or attrs.get("requestParameters", {}).get("groupName")
            or ""
        ).lower()
        targets = [t.lower() for t in conditions["group_name_contains"]]
        if not any(t in group_name for t in targets):
            return False

    if conditions.get("target_user_ne_caller"):
        target_user = str(
            attrs.get("target_user")
            or attrs.get("userName")
            or attrs.get("requestParameters", {}).get("userName")
            or ""
        ).lower()
        caller = str(event_dict.get("identity_id") or event_dict.get("raw_principal") or "").lower()
        if not target_user or target_user == caller:
            return False

    if conditions.get("activity_as_target"):
        # Check if the current event is performed by target_user from step 1
        if not matched_history:
            return False
        step1_target = matched_history[0].get("target_user", "").lower()
        caller = str(event_dict.get("identity_id") or event_dict.get("raw_principal") or "").lower()
        if not step1_target or step1_target != caller:
            return False

    if conditions.get("is_privileged_or_write"):
        action_type = context_dict.get("action_type")
        read_only = event_dict.get("read_only", False)
        priv_level = int(context_dict.get("privilege_level", 1))
        is_write = (not read_only) or action_type in (
            ActionType.write,
            ActionType.permission_change,
            ActionType.credential_change,
            ActionType.destructive,
        )
        if not (is_write or priv_level >= 3):
            return False

    return True


def check_discovery_burst(
    discovery_calls: list[dict[str, Any]],
    curr_ts: float,
    window_seconds: float = 1800.0,
    min_services: int = 5,
) -> tuple[bool, list[str]]:
    """Determine if >= min_services distinct services were discovered within window_seconds."""
    cutoff = curr_ts - window_seconds
    recent = [c for c in discovery_calls if c["timestamp"] >= cutoff]
    services = {c["service"] for c in recent if c["service"] not in ("other", "unknown")}
    if len(services) >= min_services:
        return True, [c["event_id"] for c in recent]
    return False, []


def match_privesc_paths(
    event_dict: dict[str, Any],
    context_dict: dict[str, Any],
    state: dict[str, Any],
    paths_def: list[dict[str, Any]],
    max_gap_hours: float = 168.0,
) -> list[dict[str, Any]]:
    """Pure function to evaluate events against ordered privilege escalation paths."""
    ev_id = event_dict.get("event_id", "")
    identity_id = str(event_dict.get("identity_id") or event_dict.get("raw_principal") or "")
    action = str(event_dict.get("action", ""))
    curr_ts = float(event_dict.get("timestamp", 0.0))
    attrs = event_dict.get("attrs") or {}
    max_gap_seconds = max_gap_hours * 3600.0

    if not identity_id:
        return []

    partial_matches = state.setdefault("partial_matches", {}).setdefault(identity_id, {})
    discovery_history = state.setdefault("discovery_history", {}).setdefault(identity_id, [])
    emitted_signals = state.setdefault("emitted_signals", {})

    candidate_signals: list[dict[str, Any]] = []

    # 1. Track discovery calls for PE-08
    action_cmd = action.split(":", 1)[1] if ":" in action else action
    action_cmd_lower = action_cmd.lower()
    is_discovery = (
        action_cmd_lower.startswith(("list", "get", "describe"))
        and "secret" not in action_cmd_lower
        and event_dict.get("event_class") != EventClass.data_access
    )
    if is_discovery:
        service_name = extract_service_name(event_dict)
        discovery_history.append({
            "event_id": ev_id,
            "action": action,
            "service": service_name,
            "timestamp": curr_ts,
        })
        # Keep within 30 min window + margin
        discovery_history[:] = [d for d in discovery_history if d["timestamp"] >= curr_ts - 1800.0]

    # 2. Check PE-01 through PE-07
    for path in paths_def:
        path_id = path.get("id", "")
        if path_id == "PE-08":
            continue

        steps = path.get("steps", [])
        if not steps:
            continue

        path_len = len(steps)
        current_chain = partial_matches.get(path_id, [])

        # Check gap timeout: if gap between consecutive steps exceeded, expire chain
        if current_chain:
            last_step_ts = current_chain[-1]["timestamp"]
            if (curr_ts - last_step_ts) > max_gap_seconds:
                current_chain = []
                partial_matches[path_id] = []

        next_step_index = len(current_chain)
        if next_step_index < path_len:
            target_step = steps[next_step_index]
            if matches_step_predicate(event_dict, context_dict, target_step, current_chain):
                # Matched next step!
                target_user = str(
                    attrs.get("target_user")
                    or attrs.get("userName")
                    or attrs.get("requestParameters", {}).get("userName")
                    or ""
                )
                step_record = {
                    "step_num": next_step_index + 1,
                    "event_id": ev_id,
                    "action": action,
                    "timestamp": curr_ts,
                    "stage": target_step.get("stage", "privilege_escalation"),
                    "target_user": target_user,
                }
                current_chain.append(step_record)
                partial_matches[path_id] = current_chain

                # Emit signal once at least 2 steps match (or 1 step if path length is 1)
                matched_steps_count = len(current_chain)
                if matched_steps_count >= min(2, path_len):
                    severity = float(path.get("severity", 0.9))
                    strength = round((matched_steps_count / path_len) * severity, 2)
                    signal_key = f"sig-pe-{path_id.lower()}-{identity_id}"

                    evidence_ids = [s["event_id"] for s in current_chain]
                    candidate_signals.append(
                        {
                            "signal_id": signal_key,
                            "detection_id": f"D-{path_id}",
                            "path_id": path_id,
                            "strength": strength,
                            "confidence": 0.95,
                            "evidence_event_ids": evidence_ids,
                            "mitre": path.get("mitre", ["T1098"]),
                            "stage": step_record["stage"],
                            "summary": f"Privilege escalation path {path_id} ({path.get('name')}) matched {matched_steps_count}/{path_len} steps for {identity_id}",
                            "details": {
                                "steps_matched": matched_steps_count,
                                "path_length": path_len,
                                "matched_actions": [s["action"] for s in current_chain],
                            },
                        }
                    )
                    emitted_signals[signal_key] = candidate_signals[-1]

    # 3. Check PE-08: Discovery burst -> Any PE-01..07 -> Secrets or data access
    pe08_def = next((p for p in paths_def if p.get("id") == "PE-08"), None)
    if pe08_def:
        pe08_chain = partial_matches.get("PE-08", [])
        if pe08_chain:
            last_ts = pe08_chain[-1]["timestamp"]
            if (curr_ts - last_ts) > max_gap_seconds:
                pe08_chain = []
                partial_matches["PE-08"] = []

        pe08_step_index = len(pe08_chain)

        # Step 1: Discovery burst
        if pe08_step_index == 0:
            is_burst, burst_ev_ids = check_discovery_burst(discovery_history, curr_ts)
            if is_burst:
                pe08_chain.append({
                    "step_num": 1,
                    "event_id": ev_id,
                    "evidence_ids": burst_ev_ids,
                    "action": "DiscoveryBurst",
                    "timestamp": curr_ts,
                    "stage": Stage.discovery,
                })
                partial_matches["PE-08"] = pe08_chain
        elif pe08_step_index == 1:
            has_prior_pe = any(
                len(partial_matches.get(pid, [])) >= 1
                for pid in ("PE-01", "PE-02", "PE-03", "PE-04", "PE-05", "PE-06", "PE-07")
            )
            if has_prior_pe:
                pe08_chain.append({
                    "step_num": 2,
                    "event_id": ev_id,
                    "action": action,
                    "timestamp": curr_ts,
                    "stage": Stage.privilege_escalation,
                })
                partial_matches["PE-08"] = pe08_chain

                # 2 steps of PE-08 matched -> emit candidate
                signal_key = f"sig-pe-pe-08-{identity_id}"
                cand = {
                    "signal_id": signal_key,
                    "detection_id": "D-PE-08",
                    "path_id": "PE-08",
                    "strength": 0.67,
                    "confidence": 0.95,
                    "evidence_event_ids": [s["event_id"] for s in pe08_chain],
                    "mitre": pe08_def.get("mitre", ["T1087", "T1098"]),
                    "stage": Stage.privilege_escalation,
                    "summary": f"Discovery burst followed by privilege escalation for {identity_id}",
                    "details": {"steps_matched": 2, "path_length": 3},
                }
                candidate_signals.append(cand)
                emitted_signals[signal_key] = cand
        elif pe08_step_index == 2:
            is_sensitive_access = (
                "getsecretvalue" in action_cmd_lower
                or event_dict.get("event_class") == EventClass.data_access
                or int(context_dict.get("resource_sensitivity", 1)) >= 4
            )
            if is_sensitive_access:
                pe08_chain.append({
                    "step_num": 3,
                    "event_id": ev_id,
                    "action": action,
                    "timestamp": curr_ts,
                    "stage": Stage.collection,
                })
                partial_matches["PE-08"] = pe08_chain

                signal_key = f"sig-pe-pe-08-{identity_id}"
                cand = {
                    "signal_id": signal_key,
                    "detection_id": "D-PE-08",
                    "path_id": "PE-08",
                    "strength": 1.0,
                    "confidence": 0.98,
                    "evidence_event_ids": [s["event_id"] for s in pe08_chain],
                    "mitre": pe08_def.get("mitre", ["T1087", "T1098", "T1555", "T1530"]),
                    "stage": Stage.collection,
                    "summary": f"Full attack chain PE-08 completed: Discovery -> PrivEsc -> Data Access for {identity_id}",
                    "details": {"steps_matched": 3, "path_length": 3},
                }
                candidate_signals.append(cand)
                emitted_signals[signal_key] = cand

    return candidate_signals


class PrivilegeEscalation(Agent):
    """Agent 8: Privilege Escalation detector (D-PE-01 to D-PE-08)."""

    num: ClassVar[int] = 8
    agent_id: ClassVar[str] = "agent08"
    name: ClassVar[str] = "privesc"
    layer: ClassVar[str] = "detection"
    subscribes: ClassVar[list[str]] = ["events.enriched", "sessions", "graph.updates"]
    publishes: ClassVar[list[str]] = ["signals", "deadletter"]
    path: ClassVar[str] = "warm"

    def __init__(self, paths_config_path: Path | str | None = None) -> None:
        self.paths_def = load_privesc_paths(paths_config_path)

    def init_state(self) -> dict[str, Any]:
        """Initialize state for tracking multi-step partial matches."""
        return {
            "partial_matches": {},
            "discovery_history": {},
            "emitted_signals": {},
        }

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        """Process incoming enriched events to trace privilege escalation paths."""
        if msg.topic != "events.enriched":
            return []

        payload = msg.payload
        if not isinstance(payload, EnrichedEvent):
            return []

        ev = payload.event
        cx = payload.context

        if isinstance(ev.time, str):
            try:
                event_ts = datetime.fromisoformat(ev.time).timestamp()
            except (ValueError, TypeError):
                now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
                event_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0
        elif hasattr(ev.time, "timestamp"):
            event_ts = ev.time.timestamp()
        else:
            now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
            event_ts = now_dt.timestamp() if hasattr(now_dt, "timestamp") else 0.0

        event_dict: dict[str, Any] = {
            "event_id": ev.event_id,
            "identity_id": ev.identity_id,
            "raw_principal": ev.raw_principal,
            "session_id": ev.session_id,
            "action": ev.action,
            "event_class": ev.event_class,
            "outcome": ev.outcome,
            "read_only": ev.read_only,
            "attrs": ev.attrs,
            "timestamp": event_ts,
        }

        context_dict: dict[str, Any] = {
            "action_type": cx.action_type,
            "privilege_level": cx.privilege_level,
            "resource_sensitivity": cx.resource_sensitivity,
        }

        try:
            candidates = match_privesc_paths(
                event_dict,
                context_dict,
                state,
                paths_def=self.paths_def,
                max_gap_hours=config.PRIVESC_MAX_STEP_GAP_HOURS,
            )
        except Exception:
            log.exception("Error evaluating privesc paths on event %s", ev.event_id)
            return []

        messages: list[Message] = []
        for cand in candidates:
            # Use stable signal_id so supervisor and store upgrade rather than duplicate
            sig_id = cand["signal_id"]
            sig = Signal(
                signal_id=sig_id,
                detection_id=cand["detection_id"],
                agent_num=self.num,
                identity_id=ev.identity_id,
                session_id=ev.session_id,
                strength=cand["strength"],
                confidence=cand["confidence"],
                evidence_event_ids=cand["evidence_event_ids"],
                mitre=cand["mitre"],
                stage=cand["stage"],
                summary=cand["summary"],
                details=cand.get("details", {}),
            )
            messages.append(
                ctx.new_message(
                    topic="signals",
                    payload=sig,
                    partition_key=ev.identity_id,
                    producer=self.agent_id,
                )
            )

        return messages
