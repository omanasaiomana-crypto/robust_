"""Agent 3: Context & Threat Intel for IdentityShield v3.

Follows context.md Section 5, 8, 10, 12, 13 and PRD §8, §12:
- Subscribes: events.normalized
- Publishes: events.enriched, deadletter
- Adds network, geo, threat intel flags (is_tor, is_hosting, is_proxy, trusted_ip)
- Evaluates identity privilege level (1-5) and resource sensitivity (1-5)
- Classifies action_type and stage_hint via catalog
- Non-blocking: utilizes offline reference data and cached provider results
"""
import logging
from typing import Any, ClassVar

from app.v3 import catalog
from app.v3.agents.base import Agent, AgentContext
from app.v3.enrich.offline import (
    get_privilege_level,
    get_resource_sensitivity,
    lookup_ip,
)
from app.v3.enrich.providers import ExternalEnricher
from app.v3.models import (
    Context,
    DeadletterPayload,
    EnrichedEvent,
    Event,
    Message,
)

log = logging.getLogger(__name__)


class ContextThreatIntel(Agent):
    """Agent 3: Context and Threat Intel.

    Enriches normalized events with geo/network intel, privilege levels,
    and resource sensitivity.
    """

    num = 3
    agent_id = "a03"
    name = "Context & Threat Intel"
    layer = "data"
    subscribes: ClassVar[list[str]] = ["events.normalized"]
    publishes: ClassVar[list[str]] = ["events.enriched", "deadletter"]
    path = "hot"

    def __init__(self, external_enricher: ExternalEnricher | None = None) -> None:
        self.external_enricher = external_enricher

    def init_state(self) -> dict[str, Any]:
        return {
            "processed_count": 0,
        }

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
        attrs = ev.attrs

        # 1. IP Lookup (prefers Okta attributes, falls back to geo_seed)
        ip_meta = lookup_ip(ev.src_ip, attrs)

        # 2. Check external enricher cache if enabled
        enricher = self.external_enricher
        if enricher is None and getattr(ctx.settings, "enrich_providers", None):
            db_path = getattr(ctx.store, "db_path", None) if ctx.store else None
            enricher = ExternalEnricher(db_path=db_path)

        if enricher and enricher.is_enabled():
            cached_res = enricher.get_cached(ev.src_ip)
            if cached_res:
                if not ip_meta.get("country") and cached_res.get("country"):
                    ip_meta["country"] = cached_res["country"]
                if not ip_meta.get("city") and cached_res.get("city"):
                    ip_meta["city"] = cached_res["city"]
                if not ip_meta.get("asn") and cached_res.get("asn"):
                    ip_meta["asn"] = cached_res["asn"]
                if not ip_meta.get("as_org") and cached_res.get("org"):
                    ip_meta["as_org"] = cached_res["org"]
                ip_meta["context_complete"] = True
            else:
                enricher.enqueue_prefetch(ev.src_ip)

        # 3. Privilege level (1-5)
        policy_arn = attrs.get("policy_arn")
        role_arn = attrs.get("role_arn")
        policies = [policy_arn] if policy_arn else []
        privilege = get_privilege_level(ev.identity_id, policies=policies, role_arn=role_arn)

        # 4. Resource sensitivity (1-5)
        sensitivity = get_resource_sensitivity(ev.resource_arn)

        # 5. Action type and stage hint from catalog
        cat_entry = catalog.lookup(ev.source, ev.action)

        # 6. Build Context
        context = Context(
            country=ip_meta.get("country"),
            city=ip_meta.get("city"),
            lat=ip_meta.get("lat"),
            lon=ip_meta.get("lon"),
            asn=ip_meta.get("asn"),
            as_org=ip_meta.get("as_org"),
            is_proxy=bool(ip_meta.get("is_proxy", False)),
            is_tor=bool(ip_meta.get("is_tor", False)),
            is_hosting=bool(ip_meta.get("is_hosting", False)),
            trusted_ip=bool(ip_meta.get("trusted_ip", False)),
            privilege_level=privilege,
            resource_sensitivity=sensitivity,
            action_type=cat_entry.action_type,
            stage_hint=cat_entry.stage_hint,
            context_complete=bool(ip_meta.get("context_complete", False)),
        )

        enriched_event = EnrichedEvent(event=ev, context=context)
        state["processed_count"] += 1

        out_msg = ctx.new_message(
            topic="events.enriched",
            payload=enriched_event,
            partition_key=ev.identity_id,
            producer=self.agent_id,
        )
        return [out_msg]
