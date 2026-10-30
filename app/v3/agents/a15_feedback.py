"""Agent 15: Feedback and Tuning (learning layer).

Subscribes: 'labels'
Publishes: 'config.updates', 'deadletter'

Responsibilities:
- Process analyst verdicts on cases:
  * false_positive: Lower contributing detector weights by LEARNING_RATE (floors respected)
    and create a proposed suppression rule (identity + detection + ASN) stored as 'proposed'
  * true_positive: Raise weights (+LEARNING_RATE, cap 1.0) and append confirmed case chain to
    the next-step Markov model training set
  * benign_true_positive: Create a 24-hour time-boxed suppression rule active immediately
- Golden Rule guardrail: Never lower D-PE-* or D-DEF-* weights below 0.6 floor
- Every change is versioned in config_versions_v3, audited, and published on 'config.updates'
- Support rollback to any previous configuration version
"""
import json
import logging
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from app.v3 import audit, store
from app.v3 import config as v3_cfg
from app.v3.agents.base import Agent, AgentContext
from app.v3.models import (
    Case,
    ConfigUpdate,
    DeadletterPayload,
    Label,
    Message,
    Verdict,
)

log = logging.getLogger(__name__)

_DETECTION_RE = re.compile(r"D-[A-Z]{2,4}-\d{2}")


class FeedbackAgent(Agent):
    """Agent 15: Feedback, calibration, and policy tuning."""

    num = 15
    agent_id = "a15"
    name = "Feedback & Tuning"
    layer = "learning"
    subscribes: ClassVar[list[str]] = ["labels"]
    publishes: ClassVar[list[str]] = ["config.updates", "deadletter"]
    path = "warm"

    def __init__(self) -> None:
        self._weights: dict[str, float] = {}
        self._training_chains: list[list[str]] = []
        self._proposed_suppressions: list[dict[str, Any]] = []
        self._active_suppressions: list[dict[str, Any]] = []
        self._initialized = False

    def init_state(self) -> dict[str, Any]:
        return {
            "version": 1,
            "weights": dict(self._weights),
            "training_chains": list(self._training_chains),
            "proposed_suppressions": list(self._proposed_suppressions),
            "active_suppressions": list(self._active_suppressions),
        }

    def _ensure_initialized(self) -> None:
        """Load latest config version from config_versions_v3 if available."""
        if self._initialized:
            return
        self._initialized = True
        try:
            row = store.fetch_one("SELECT * FROM config_versions_v3 ORDER BY version DESC LIMIT 1")
            if row:
                changes = json.loads(row["changes"])
                self._weights = changes.get("weights", {})
                self._training_chains = changes.get("training_chains", [])
                self._proposed_suppressions = changes.get("proposed_suppressions", [])
                self._active_suppressions = changes.get("active_suppressions", [])
        except (sqlite3.Error, json.JSONDecodeError, OSError) as exc:
            log.debug("No existing config version found or table not ready: %s", exc)

    def get_weight(self, detection_id: str) -> float:
        self._ensure_initialized()
        return self._weights.get(detection_id, 1.0)

    def get_all_weights(self) -> dict[str, float]:
        self._ensure_initialized()
        return dict(self._weights)

    def get_active_suppressions(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        return list(self._active_suppressions)

    def get_proposed_suppressions(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        return list(self._proposed_suppressions)

    def _extract_contributing_detections(self, case: Case | None, label: Label) -> list[str]:
        detections: set[str] = set()
        if not case:
            # Fallback to note or direct pattern regex
            for m in _DETECTION_RE.finditer(label.note or ""):
                detections.add(m.group(0))
            return sorted(detections) or ["D-ACC-02"]

        # 1. From signal_ids
        for sid in case.signal_ids:
            for m in _DETECTION_RE.finditer(sid):
                detections.add(m.group(0))

        # 2. Query signals_v3
        if case.signal_ids:
            try:
                placeholders = ", ".join(["?"] * len(case.signal_ids))
                rows = store.fetch_all(
                    f"SELECT detection_id FROM signals_v3 WHERE signal_id IN ({placeholders})",
                    list(case.signal_ids),
                )
                for r in rows:
                    if r.get("detection_id"):
                        detections.add(r["detection_id"])
            except (sqlite3.Error, OSError) as exc:
                log.debug("Signals lookup failed in feedback: %s", exc)

        # 3. From case reasons
        for r in case.reasons:
            for m in _DETECTION_RE.finditer(r.text):
                detections.add(m.group(0))

        # 4. From case chain
        for step in case.chain:
            for m in _DETECTION_RE.finditer(step.action):
                detections.add(m.group(0))

        return sorted(detections) or ["D-ACC-02"]

    def _extract_case_asn(self, case: Case | None) -> str:
        if not case:
            return "unknown"
        # Check sessions_v3 or events_v3
        try:
            if case.session_id:
                s_row = store.fetch_one("SELECT asns FROM sessions_v3 WHERE session_id = ?", (case.session_id,))
                if s_row and s_row["asns"]:
                    asns = json.loads(s_row["asns"])
                    if asns:
                        return str(asns[0])
            e_row = store.fetch_one(
                "SELECT attrs FROM events_v3 WHERE identity_id = ? ORDER BY time DESC LIMIT 1",
                (case.identity_id,),
            )
            if e_row and e_row["attrs"]:
                attrs = json.loads(e_row["attrs"])
                if attrs.get("asn"):
                    return str(attrs["asn"])
        except (sqlite3.Error, json.JSONDecodeError, OSError) as exc:
            log.debug("ASN lookup failed in feedback: %s", exc)
        return "AS15169"

    def _get_next_version(self) -> int:
        try:
            row = store.fetch_one("SELECT MAX(version) AS max_v FROM config_versions_v3")
            if row and row["max_v"] is not None:
                return int(row["max_v"]) + 1
        except (sqlite3.Error, OSError) as exc:
            log.debug("Version lookup failed in feedback: %s", exc)
        return 1

    def _persist_config_version(
        self,
        version: int,
        changes: dict[str, Any],
        reason: str,
        created_at: str,
        created_by: str = "agent15",
    ) -> None:
        try:
            store.insert_many("config_versions_v3", [{
                "version": version,
                "changes": json.dumps(changes, sort_keys=True),
                "reason": reason,
                "created_at": created_at,
                "created_by": created_by,
            }])
        except (sqlite3.Error, OSError) as exc:
            log.warning("Failed to persist config_versions_v3: %s", exc)

    def rollback(
        self,
        target_version: int,
        analyst: str = "analyst",
        now_dt: datetime | None = None,
    ) -> ConfigUpdate:
        """Rollback configuration to target_version, creating a new version with restored weights."""
        self._ensure_initialized()
        row = store.fetch_one("SELECT * FROM config_versions_v3 WHERE version = ?", (target_version,))
        if not row:
            raise ValueError(f"Config version {target_version} not found in config_versions_v3")

        past_changes = json.loads(row["changes"])
        self._weights = past_changes.get("weights", {})
        self._proposed_suppressions = past_changes.get("proposed_suppressions", [])
        self._active_suppressions = past_changes.get("active_suppressions", [])
        self._training_chains = past_changes.get("training_chains", [])

        now = now_dt or datetime.now(UTC)
        now_iso = now.isoformat()
        new_version = self._get_next_version()
        reason = f"Rollback to config version {target_version} by {analyst}"

        new_changes = {
            "weights": dict(self._weights),
            "proposed_suppressions": list(self._proposed_suppressions),
            "active_suppressions": list(self._active_suppressions),
            "training_chains_count": len(self._training_chains),
            "rolled_back_from": target_version,
        }

        self._persist_config_version(new_version, new_changes, reason, now_iso, created_by=analyst)
        audit.append("a15", "config_rollback", {
            "target_version": target_version,
            "new_version": new_version,
            "analyst": analyst,
        })

        return ConfigUpdate(
            kind="config_update",
            version=new_version,
            changes=new_changes,
            reason=reason,
            created_at=now_iso,
            created_by=analyst,
        )

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        self._ensure_initialized()
        if msg.topic != "labels" or not isinstance(msg.payload, Label):
            return []

        label: Label = msg.payload
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_iso = now_dt.isoformat()

        # 1. Record label in labels_v3
        try:
            store.insert_many("labels_v3", [{
                "case_id": label.case_id,
                "verdict": label.verdict.value if hasattr(label.verdict, "value") else str(label.verdict),
                "analyst": label.analyst,
                "note": label.note,
                "created_at": label.time or now_iso,
            }])
        except (sqlite3.Error, OSError) as exc:
            log.warning("Failed to insert label for case %s: %s", label.case_id, exc)

        # 2. Fetch case details
        case: Case | None = None
        c_row = store.fetch_one("SELECT * FROM cases_v3 WHERE case_id = ?", (label.case_id,))
        if c_row:
            try:
                case = Case(
                    case_id=c_row["case_id"],
                    identity_id=c_row["identity_id"],
                    session_id=c_row["session_id"],
                    session_risk=c_row["session_risk"],
                    identity_risk=c_row["identity_risk"],
                    confidence=c_row["confidence"],
                    band=c_row["band"],
                    status=c_row["status"],
                    signal_ids=json.loads(c_row["signal_ids"]),
                    chain=json.loads(c_row["chain"]),
                    reasons=json.loads(c_row["reasons"]),
                    counterfactuals=json.loads(c_row["counterfactuals"]),
                    next_steps=json.loads(c_row["next_steps"]),
                    blast_radius=c_row["blast_radius"],
                    related_identities=json.loads(c_row["related_identities"]),
                    narrative=c_row["narrative"],
                    narrative_source=c_row["narrative_source"],
                    created_at=c_row["created_at"],
                    updated_at=c_row["updated_at"],
                )
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                log.debug("Failed to reconstruct case %s in feedback: %s", c_row["case_id"], exc)

        contributing = self._extract_contributing_detections(case, label)
        identity_id = case.identity_id if case else "unknown"
        asn = self._extract_case_asn(case)
        lr = getattr(ctx.settings, "learning_rate", v3_cfg.LEARNING_RATE)

        verdict_val = label.verdict.value if hasattr(label.verdict, "value") else str(label.verdict)

        if verdict_val == Verdict.false_positive.value:
            # Lower weights down to floors
            for det in contributing:
                cur = self._weights.get(det, 1.0)
                # Floors: D-PE and D-DEF >= 0.6
                if det.startswith(("D-PE", "D-DEF")):
                    floor = 0.6
                else:
                    floor = 0.1
                new_w = max(floor, cur - lr)
                self._weights[det] = round(new_w, 4)

            # Proposed suppression (inactive until analyst approves via API)
            prop = {
                "identity_id": identity_id,
                "detection_ids": contributing,
                "asn": asn,
                "status": "proposed",
                "created_at": now_iso,
                "created_by": label.analyst,
            }
            self._proposed_suppressions.append(prop)
            reason = f"FP label on case {label.case_id}: lowered weights for {contributing}, proposed suppression"

        elif verdict_val == Verdict.true_positive.value:
            # Raise weights, cap 1.0
            for det in contributing:
                cur = self._weights.get(det, 1.0)
                new_w = min(1.0, cur + lr)
                self._weights[det] = round(new_w, 4)

            # Append confirmed case chain to next-step model training set
            if case and case.chain:
                chain_actions = [step.action if hasattr(step, "action") else str(step) for step in case.chain]
                self._training_chains.append(chain_actions)
            reason = f"TP label on case {label.case_id}: raised weights for {contributing}, appended chain to Markov model"

        elif verdict_val == Verdict.benign_true_positive.value:
            # 24-hour time-boxed suppression active immediately
            exp_iso = (now_dt + timedelta(hours=24)).isoformat()
            act_supp = {
                "identity_id": identity_id,
                "detection_ids": contributing,
                "asn": asn,
                "status": "active",
                "expires_at": exp_iso,
                "created_at": now_iso,
                "created_by": label.analyst,
            }
            self._active_suppressions.append(act_supp)
            reason = f"Benign TP label on case {label.case_id}: 24h suppression active immediately"

        else:
            return [ctx.new_message(
                topic="deadletter",
                payload=DeadletterPayload(
                    failed_topic="labels",
                    error=f"Unknown verdict {label.verdict}",
                    producer=self.agent_id,
                ),
                producer=self.agent_id,
            )]

        # Create new config version
        new_version = self._get_next_version()
        changes = {
            "weights": dict(self._weights),
            "proposed_suppressions": list(self._proposed_suppressions),
            "active_suppressions": list(self._active_suppressions),
            "training_chains_count": len(self._training_chains),
            "last_label_case_id": label.case_id,
        }

        self._persist_config_version(new_version, changes, reason, now_iso, created_by=label.analyst)
        audit.append("a15", "config_update", {
            "version": new_version,
            "verdict": verdict_val,
            "reason": reason,
        })

        update_payload = ConfigUpdate(
            kind="config_update",
            version=new_version,
            changes=changes,
            reason=reason,
            created_at=now_iso,
            created_by="agent15",
        )

        state["version"] = new_version
        state["weights"] = dict(self._weights)
        state["proposed_suppressions"] = list(self._proposed_suppressions)
        state["active_suppressions"] = list(self._active_suppressions)
        state["training_chains"] = list(self._training_chains)

        return [ctx.new_message(topic="config.updates", payload=update_payload, producer=self.agent_id)]
