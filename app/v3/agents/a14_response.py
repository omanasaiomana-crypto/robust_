"""Agent 14: Response (decision layer).

Subscribes: 'cases', 'approvals'
Publishes: 'actions', 'deadletter'

Responsibilities:
- Load and validate policy-as-code playbooks from default.yaml at startup
- Match highest-priority playbook per case (defense-evasion PB-04 first, then by band)
- Enforce friction budget per identity (FRICTION_UNITS per FRICTION_WINDOW_HOURS)
- Execute action lifecycle: proposed -> pending_approval -> approved | rejected | expired
  -> executing -> applied | failed -> rolled_back
- Safe simulator adapter enforcement (Golden Rule 1: only through simulator; idempotent)
- Revoke always requires analyst approval (Golden Rule 3)
- Restrict TTL auto-expiry and rollback on tick
- Admin notification via app/notify.py with HTML escaping and rate-limiting
- Audit trail for every state transition
"""
import html
import json
import logging
import sqlite3
import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, ClassVar

import yaml

from app.v3 import audit, store
from app.v3 import config as v3_cfg
from app.v3.agents.base import Agent, AgentContext
from app.v3.config import Settings
from app.v3.models import (
    Action,
    ActionKind,
    ActionState,
    Case,
    CaseStatus,
    DeadletterPayload,
    Message,
)
from app.v3.supervisor import CapabilityError

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Simulator Adapter Client (Idempotent & Capability Checked)
# ---------------------------------------------------------------------------


class SimulatorClient:
    """Thin wrapper around app.simulator ensuring capability and idempotency."""

    def __init__(self, simulator_instance: Any = None) -> None:
        self._sim = simulator_instance
        self._executed: dict[str, str] = {}  # action_id -> ref

    def _get_sim(self) -> Any:
        if self._sim is None:
            from app.simulator import get_simulator

            self._sim = get_simulator()
        return self._sim

    def execute(
        self,
        action_kind: ActionKind | str,
        identity_id: str,
        session_id: str | None = None,
        action_id: str | None = None,
        scope: str = "default",
        caller: Any = "a14",
        dry_run: bool = False,
    ) -> str:
        """Execute action via simulator.

        Enforces Agent 14 capability and idempotency by action_id.
        """
        # Capability check
        num = getattr(caller, "num", caller)
        if isinstance(num, str):
            if num in ("a14", "14"):
                num = 14
            elif num in ("a13", "13"):
                num = 13
            else:
                num = -1
        if num != 14:
            raise CapabilityError(f"Agent {caller} (num {num}) capability manifest forbids simulator access")

        if dry_run:
            return "applied (dry run)"

        if action_id and action_id in self._executed:
            return self._executed[action_id]

        sim = self._get_sim()
        kind_str = action_kind.value if hasattr(action_kind, "value") else str(action_kind)

        def _do_call() -> Any:
            if kind_str == "step_up":
                return sim.step_up(identity_id=identity_id, session_id=session_id)
            if kind_str in ("restrict", "quarantine_identity"):
                return sim.restrict(identity_id=identity_id, scope=scope)
            if kind_str in ("revoke_sessions", "revoke"):
                return sim.revoke(identity_id=identity_id, session_id=session_id)
            if kind_str == "block_ip":
                if hasattr(sim, "block_ip"):
                    return sim.block_ip(identity_id)
                return f"simulated:block_ip:{identity_id}:ok"
            if kind_str == "disable_key":
                if hasattr(sim, "disable_key"):
                    return sim.disable_key(identity_id)
                return f"simulated:disable_key:{identity_id}:ok"
            if kind_str == "monitor":
                return "simulated:monitor:ok"
            return f"simulated:{kind_str}:ok"

        # Retry once on failure
        try:
            res = _do_call()
        except (RuntimeError, ValueError, TypeError, OSError):
            res = _do_call()

        ref = str(res)
        if action_id:
            self._executed[action_id] = ref
        return ref

    def rollback(
        self,
        rollback_action: str | None,
        identity_id: str,
        action_id: str | None = None,
        caller: Any = "a14",
        dry_run: bool = False,
    ) -> str:
        """Rollback an applied action via simulator."""
        num = getattr(caller, "num", caller)
        if isinstance(num, str):
            if num in ("a14", "14"):
                num = 14
            else:
                num = -1
        if num != 14:
            raise CapabilityError(f"Agent {caller} (num {num}) capability manifest forbids simulator access")

        if dry_run:
            return "rolled_back (dry run)"

        action_name = rollback_action or "revert_restrict"
        sim = self._get_sim()
        if hasattr(sim, action_name):
            try:
                fn = getattr(sim, action_name)
                return str(fn(identity_id))
            except (RuntimeError, ValueError, TypeError, OSError) as exc:
                log.debug("Simulator rollback call failed: %s", exc)
        return f"simulated:{action_name}:{identity_id}:ok"


# Global singleton client instance
_simulator_client = SimulatorClient()


def get_simulator_client() -> SimulatorClient:
    return _simulator_client


def execute_simulator_action(
    action_kind: ActionKind | str,
    identity_id: str,
    session_id: str | None = None,
    action_id: str | None = None,
    scope: str = "default",
    caller: Any = "a14",
    dry_run: bool = False,
) -> str:
    return _simulator_client.execute(
        action_kind=action_kind,
        identity_id=identity_id,
        session_id=session_id,
        action_id=action_id,
        scope=scope,
        caller=caller,
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Playbook Loader and Validator
# ---------------------------------------------------------------------------


def load_playbooks(yaml_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Load and validate playbooks from YAML. Raises ValueError with clear message on error."""
    target = Path(yaml_path) if yaml_path else (Path(__file__).resolve().parent.parent / "playbooks" / "default.yaml")
    if not target.is_file():
        raise ValueError(f"Playbooks configuration file not found: {target}")

    try:
        content = target.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except Exception as exc:
        raise ValueError(f"Failed to parse playbooks YAML file {target}: {exc}") from exc

    if not isinstance(data, dict) or "playbooks" not in data or not isinstance(data["playbooks"], list):
        raise ValueError(f"Invalid playbooks YAML in {target}: top-level 'playbooks' list required")

    required_fields = {"id", "match", "action", "approval_required", "ttl_minutes", "friction_cost"}
    playbooks: list[dict[str, Any]] = []

    for item in data["playbooks"]:
        if not isinstance(item, dict):
            raise TypeError(f"Invalid playbook entry (must be a mapping): {item}")
        missing = required_fields - set(item.keys())
        if missing:
            raise ValueError(f"Playbook {item.get('id', '?')} missing required fields: {sorted(missing)}")
        # Validate action kind
        try:
            ActionKind(item["action"])
        except ValueError as exc:
            raise ValueError(f"Playbook {item['id']} has invalid action kind '{item['action']}': {exc}") from exc
        playbooks.append(item)

    return playbooks


def match_playbook(case: Case, playbooks: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """Select the highest-priority playbook for a case.

    Priority order:
    1. PB-04: defense evasion (overrides band)
    2. PB-05: coordinated campaign source IP block
    3. Band-based match (PB-03 for revoke, PB-02 for restrict, PB-01 for step_up)
    """
    # 1. PB-04 Defense evasion check first:
    pb04 = next((p for p in playbooks if p.get("id") == "PB-04"), None)
    if pb04:
        patterns = pb04.get("match", {}).get("patterns", ["D-DEF-01", "D-DEF-02"])
        has_defense_evasion = False
        for pat in patterns:
            if any(pat in sid for sid in case.signal_ids):
                has_defense_evasion = True
                break
            if any(pat in step.action or (step.mitre and any(pat in m for m in step.mitre)) for step in case.chain):
                has_defense_evasion = True
                break
            if any(pat in r.text for r in case.reasons):
                has_defense_evasion = True
                break
        if has_defense_evasion:
            return pb04

    # 2. PB-05 Campaign check:
    pb05 = next((p for p in playbooks if p.get("id") == "PB-05"), None)
    if pb05:
        patterns = pb05.get("match", {}).get("patterns", ["D-CMP-01"])
        if any(
            any(pat in sid for sid in case.signal_ids)
            or any(pat in r.text for r in case.reasons)
            for pat in patterns
        ):
            return pb05

    # 3. Match by band:
    band_str = case.band.value if hasattr(case.band, "value") else str(case.band)
    for pb in playbooks:
        if pb.get("id") in ("PB-04", "PB-05"):
            continue
        bands = pb.get("match", {}).get("band", [])
        if band_str in bands:
            return pb

    return None


# ---------------------------------------------------------------------------
# Email Notifier Integration
# ---------------------------------------------------------------------------


def send_case_notification(
    case: Case,
    settings: Settings,
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    """Send one email per case at band >= EMAIL_MIN_BAND (default 'restrict'), with deduplication."""
    from app import notify

    min_band = getattr(settings, "email_min_band", v3_cfg.EMAIL_MIN_BAND)
    band_val = case.band.value if hasattr(case.band, "value") else str(case.band)
    allowed_bands = ("restrict", "revoke") if min_band == "restrict" else ("revoke",)
    if band_val not in allowed_bands and case.identity_risk < 70.0:
        return None

    fp = f"case:{case.case_id}"
    try:
        rows = store.fetch_all(
            "SELECT id FROM notifications WHERE fingerprints LIKE ? OR alert_ids LIKE ?",
            (f"%{fp}%", f"%{case.case_id}%"),
            db_path=db_path,
        )
        if rows:
            return None
    except (sqlite3.Error, OSError) as exc:
        log.debug("Notifications check failed: %s", exc)

    level = "CRITICAL" if band_val == "revoke" else "HIGH"
    top_reason = case.reasons[0].text if case.reasons else "Suspicious identity activity"
    subj = notify.clean_header(
        f"[IdentityShield] {level}: Case {case.case_id} - {case.identity_id} (risk {case.identity_risk:.0f})"
    )

    lines = [
        f"IdentityShield detected high-risk identity activity for case {notify.clean_header(case.case_id)}.",
        "",
        f"Identity: {notify.clean_header(case.identity_id)}",
        f"Session: {notify.clean_header(case.session_id)}",
        f"Band: {band_val.upper()}",
        f"Identity Risk: {case.identity_risk:.1f}",
        f"Session Risk: {case.session_risk:.1f}",
        f"Status: {case.status.value if hasattr(case.status, 'value') else case.status}",
        f"Top Reason: {notify.clean_header(top_reason)}",
        "",
        "No session was revoked automatically. Revocation always requires analyst approval.",
        "This is an automated message from IdentityShield.",
    ]
    text = "\n".join(lines)

    html_body = (
        "<div style='font-family:Arial,sans-serif;color:#111827'>"
        f"<h2 style='margin:0 0 8px'>{html.escape(level)}: Suspicious Identity Activity</h2>"
        f"<p>Case <b>{html.escape(case.case_id)}</b> triggered an alert.</p>"
        "<table style='border-collapse:collapse;font-size:14px'>"
        f"<tr><td><b>Identity</b></td><td>{html.escape(case.identity_id)}</td></tr>"
        f"<tr><td><b>Session</b></td><td>{html.escape(case.session_id)}</td></tr>"
        f"<tr><td><b>Band</b></td><td>{html.escape(band_val)}</td></tr>"
        f"<tr><td><b>Risk Score</b></td><td>{case.identity_risk:.1f}</td></tr>"
        f"<tr><td><b>Reason</b></td><td>{html.escape(top_reason)}</td></tr>"
        "</table>"
        "<p style='color:#6b7280;font-size:12px;margin-top:12px'>"
        "No session was revoked automatically. Revocation always requires analyst approval.</p>"
        "</div>"
    )

    msg = EmailMessage()
    msg["Subject"] = subj
    msg["From"] = notify.clean_header(getattr(settings, "alert_email_from", "identityshield@yourcompany.com"))
    recipients = notify.valid_recipients()
    msg["To"] = ", ".join(recipients) or "admin@localhost"
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="identityshield.local")
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")

    return notify.deliver(msg, text, kind="case_alert", alert_ids=[case.case_id], fps=[fp])


# ---------------------------------------------------------------------------
# Agent 14: Response
# ---------------------------------------------------------------------------


class ResponseAgent(Agent):
    """Agent 14: Response and Playbook Enforcement."""

    num = 14
    agent_id = "a14"
    name = "Response"
    layer = "decision"
    subscribes: ClassVar[list[str]] = ["cases", "approvals"]
    publishes: ClassVar[list[str]] = ["actions", "deadletter"]
    path = "warm"

    def __init__(
        self,
        playbooks_path: Path | str | None = None,
        simulator: SimulatorClient | None = None,
    ) -> None:
        self._playbooks = load_playbooks(playbooks_path)
        self._sim_client = simulator or get_simulator_client()

    def init_state(self) -> dict[str, Any]:
        return {
            "friction_spends": {},  # identity_id -> list of iso_timestamps
            "actions": {},  # action_id -> dict
            "notified_cases": set(),  # case_ids already emailed
        }

    def _clean_friction_spends(
        self,
        spends: list[str],
        now: datetime,
        window_hours: int,
    ) -> list[str]:
        cutoff = now - timedelta(hours=window_hours)
        valid: list[str] = []
        for s in spends:
            try:
                dt = datetime.fromisoformat(s)
                if dt >= cutoff:
                    valid.append(s)
            except (ValueError, TypeError):
                continue
        return valid

    def _persist_action(self, action: Action, db_path: Path | str | None = None) -> None:
        row = {
            "action_id": action.action_id,
            "case_id": action.case_id,
            "playbook_id": action.playbook_id,
            "action_kind": action.action_kind.value if hasattr(action.action_kind, "value") else str(action.action_kind),
            "approval_required": 1 if action.approval_required else 0,
            "state": action.state.value if hasattr(action.state, "value") else str(action.state),
            "simulator_ref": action.simulator_ref,
            "reason": action.reason,
            "created_at": action.created_at,
            "updated_at": action.updated_at,
            "expires_at": action.expires_at,
            "approved_by": action.approved_by,
        }
        try:
            store.insert_many("actions_v3", [row], db_path=db_path)
        except (sqlite3.Error, OSError) as exc:
            log.warning("Failed to persist action %s to actions_v3: %s", action.action_id, exc)

    def _update_case_status(
        self,
        case_id: str,
        status: CaseStatus,
        now_iso: str,
        db_path: Path | str | None = None,
    ) -> None:
        try:
            store.execute(
                "UPDATE cases_v3 SET status = ?, updated_at = ? WHERE case_id = ?",
                (status.value, now_iso, case_id),
                db_path=db_path,
            )
        except (sqlite3.Error, OSError) as exc:
            log.warning("Failed to update case %s status: %s", case_id, exc)

    def process(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
    ) -> list[Message]:
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_iso = now_dt.isoformat()
        dry_run = getattr(ctx.settings, "dry_run", v3_cfg.DRY_RUN)

        if msg.topic == "cases" and isinstance(msg.payload, Case):
            case = msg.payload
            out_msgs: list[Message] = []

            # 1. Send notification email if eligible
            notified = state.setdefault("notified_cases", set())
            if case.case_id not in notified:
                send_case_notification(case, ctx.settings)
                notified.add(case.case_id)

            # 2. Match playbook
            pb = match_playbook(case, self._playbooks)
            if not pb:
                return []

            # 3. Handle PB-03 special case: immediate restrict + pending revoke
            if pb["id"] == "PB-03":
                # a) Execute immediate restrict (PB-02 semantics, non-approval)
                restr_id = f"act-{uuid.uuid4().hex[:12]}"
                restr_expires = (now_dt + timedelta(minutes=240)).isoformat()
                sim_ref = self._sim_client.execute(
                    action_kind=ActionKind.restrict,
                    identity_id=case.identity_id,
                    session_id=case.session_id,
                    action_id=restr_id,
                    caller=self,
                    dry_run=dry_run,
                )
                act_restrict = Action(
                    action_id=restr_id,
                    case_id=case.case_id,
                    playbook_id="PB-02",
                    action_kind=ActionKind.restrict,
                    approval_required=False,
                    state=ActionState.applied,
                    simulator_ref=sim_ref,
                    reason="PB-03 immediate containment restrict",
                    created_at=now_iso,
                    updated_at=now_iso,
                    expires_at=restr_expires,
                )
                self._persist_action(act_restrict)
                audit.append("a14", "action_applied", {
                    "action_id": act_restrict.action_id,
                    "case_id": case.case_id,
                    "kind": "restrict",
                    "ref": sim_ref,
                })
                state["actions"][act_restrict.action_id] = act_restrict
                out_msgs.append(ctx.new_message(topic="actions", payload=act_restrict, producer=self.agent_id))

                # b) Propose revoke_sessions pending approval
                rev_id = f"act-{uuid.uuid4().hex[:12]}"
                rev_expires = (now_dt + timedelta(minutes=v3_cfg.APPROVAL_TIMEOUT_MINUTES)).isoformat()
                act_revoke = Action(
                    action_id=rev_id,
                    case_id=case.case_id,
                    playbook_id="PB-03",
                    action_kind=ActionKind.revoke_sessions,
                    approval_required=True,
                    state=ActionState.pending_approval,
                    reason="PB-03 session revocation pending analyst approval",
                    created_at=now_iso,
                    updated_at=now_iso,
                    expires_at=rev_expires,
                )
                self._persist_action(act_revoke)
                audit.append("a14", "action_proposed", {
                    "action_id": act_revoke.action_id,
                    "case_id": case.case_id,
                    "kind": "revoke_sessions",
                    "approval_required": True,
                })
                self._update_case_status(case.case_id, CaseStatus.awaiting_approval, now_iso)
                state["actions"][act_revoke.action_id] = act_revoke
                out_msgs.append(ctx.new_message(topic="actions", payload=act_revoke, producer=self.agent_id))
                return out_msgs

            # 4. Standard playbook execution (PB-01, PB-02, PB-04, PB-05)
            action_kind = ActionKind(pb["action"])
            reason = f"Playbook {pb['id']} triggered"

            # Check friction budget for step_up
            if action_kind == ActionKind.step_up:
                spends = state.setdefault("friction_spends", {}).setdefault(case.identity_id, [])
                spends = self._clean_friction_spends(spends, now_dt, v3_cfg.FRICTION_WINDOW_HOURS)
                state["friction_spends"][case.identity_id] = spends

                if len(spends) >= v3_cfg.FRICTION_UNITS:
                    action_kind = ActionKind.monitor
                    reason = "friction budget exhausted, escalated to analyst"
                else:
                    spends.append(now_iso)

            approval_req = bool(pb.get("approval_required", False))
            act_id = f"act-{uuid.uuid4().hex[:12]}"
            ttl_min = pb.get("ttl_minutes")
            expires_at = (now_dt + timedelta(minutes=ttl_min)).isoformat() if ttl_min else None

            if approval_req:
                rev_expires = (now_dt + timedelta(minutes=v3_cfg.APPROVAL_TIMEOUT_MINUTES)).isoformat()
                action = Action(
                    action_id=act_id,
                    case_id=case.case_id,
                    playbook_id=pb["id"],
                    action_kind=action_kind,
                    approval_required=True,
                    state=ActionState.pending_approval,
                    reason=reason,
                    created_at=now_iso,
                    updated_at=now_iso,
                    expires_at=rev_expires,
                )
                self._persist_action(action)
                audit.append("a14", "action_proposed", {
                    "action_id": action.action_id,
                    "case_id": case.case_id,
                    "kind": action_kind.value,
                })
                self._update_case_status(case.case_id, CaseStatus.awaiting_approval, now_iso)
                state["actions"][action.action_id] = action
                out_msgs.append(ctx.new_message(topic="actions", payload=action, producer=self.agent_id))
                return out_msgs

            # Non-approval actions execute immediately
            sim_ref = self._sim_client.execute(
                action_kind=action_kind,
                identity_id=case.identity_id,
                session_id=case.session_id,
                action_id=act_id,
                caller=self,
                dry_run=dry_run,
            )
            action = Action(
                action_id=act_id,
                case_id=case.case_id,
                playbook_id=pb["id"],
                action_kind=action_kind,
                approval_required=False,
                state=ActionState.applied,
                simulator_ref=sim_ref,
                reason=reason,
                created_at=now_iso,
                updated_at=now_iso,
                expires_at=expires_at,
            )
            self._persist_action(action)
            audit.append("a14", "action_applied", {
                "action_id": action.action_id,
                "case_id": case.case_id,
                "kind": action_kind.value,
                "ref": sim_ref,
            })
            if action_kind in (ActionKind.restrict, ActionKind.block_ip, ActionKind.quarantine_identity):
                self._update_case_status(case.case_id, CaseStatus.contained, now_iso)
            state["actions"][action.action_id] = action
            out_msgs.append(ctx.new_message(topic="actions", payload=action, producer=self.agent_id))
            return out_msgs

        if msg.topic == "approvals":
            return self._handle_approval_message(msg, state, ctx, now_dt, now_iso, dry_run)

        return []

    def _handle_approval_message(
        self,
        msg: Message,
        state: dict[str, Any],
        ctx: AgentContext,
        now_dt: datetime,
        now_iso: str,
        dry_run: bool,
    ) -> list[Message]:
        payload = msg.payload
        act_id: str | None = None
        decision: str | None = None
        analyst: str = "analyst"

        if isinstance(payload, Action):
            act_id = payload.action_id
            decision = payload.state.value if hasattr(payload.state, "value") else str(payload.state)
            analyst = payload.approved_by or "analyst"
        elif hasattr(payload, "raw_text") and getattr(payload, "raw_text", None):
            try:
                parsed = json.loads(payload.raw_text)
                act_id = parsed.get("action_id")
                decision = parsed.get("decision") or parsed.get("action")
                analyst = parsed.get("analyst", "analyst")
            except (json.JSONDecodeError, ValueError, TypeError) as exc:
                log.debug("Could not parse raw approval text: %s", exc)
        elif isinstance(payload, dict):
            act_id = payload.get("action_id")
            decision = payload.get("decision") or payload.get("action")
            analyst = payload.get("analyst", "analyst")

        if not act_id:
            return [ctx.new_message(
                topic="deadletter",
                payload=DeadletterPayload(
                    failed_topic="approvals",
                    error="Missing action_id in approval message",
                    producer=self.agent_id,
                ),
                producer=self.agent_id,
            )]

        # Fetch existing action
        existing: Action | None = state.get("actions", {}).get(act_id)
        if not existing:
            row = store.fetch_one("SELECT * FROM actions_v3 WHERE action_id = ?", (act_id,))
            if row:
                existing = Action(
                    action_id=row["action_id"],
                    case_id=row["case_id"],
                    playbook_id=row["playbook_id"],
                    action_kind=ActionKind(row["action_kind"]),
                    approval_required=bool(row["approval_required"]),
                    state=ActionState(row["state"]),
                    simulator_ref=row["simulator_ref"],
                    reason=row["reason"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    expires_at=row["expires_at"],
                    approved_by=row["approved_by"],
                )

        if not existing:
            return [ctx.new_message(
                topic="deadletter",
                payload=DeadletterPayload(
                    failed_topic="approvals",
                    error=f"Action {act_id} not found",
                    producer=self.agent_id,
                ),
                producer=self.agent_id,
            )]

        dec = str(decision).lower()
        if dec in ("approve", "approved"):
            sim_ref = self._sim_client.execute(
                action_kind=existing.action_kind,
                identity_id=existing.case_id,
                action_id=existing.action_id,
                caller=self,
                dry_run=dry_run,
            )
            updated = Action(
                action_id=existing.action_id,
                case_id=existing.case_id,
                playbook_id=existing.playbook_id,
                action_kind=existing.action_kind,
                approval_required=existing.approval_required,
                state=ActionState.applied,
                simulator_ref=sim_ref,
                reason=existing.reason,
                created_at=existing.created_at,
                updated_at=now_iso,
                expires_at=existing.expires_at,
                approved_by=analyst,
            )
            self._persist_action(updated)
            self._update_case_status(existing.case_id, CaseStatus.contained, now_iso)
            audit.append("a14", "action_approved", {
                "action_id": updated.action_id,
                "case_id": updated.case_id,
                "analyst": analyst,
            })
            state.setdefault("actions", {})[updated.action_id] = updated
            return [ctx.new_message(topic="actions", payload=updated, producer=self.agent_id)]

        if dec in ("reject", "rejected"):
            updated = Action(
                action_id=existing.action_id,
                case_id=existing.case_id,
                playbook_id=existing.playbook_id,
                action_kind=existing.action_kind,
                approval_required=existing.approval_required,
                state=ActionState.rejected,
                simulator_ref=existing.simulator_ref,
                reason=existing.reason,
                created_at=existing.created_at,
                updated_at=now_iso,
                expires_at=existing.expires_at,
                approved_by=analyst,
            )
            self._persist_action(updated)
            audit.append("a14", "action_rejected", {
                "action_id": updated.action_id,
                "case_id": updated.case_id,
                "analyst": analyst,
            })
            state.setdefault("actions", {})[updated.action_id] = updated
            return [ctx.new_message(topic="actions", payload=updated, producer=self.agent_id)]

        if dec in ("rollback", "rolled_back"):
            sim_ref = self._sim_client.rollback(
                rollback_action="revert_restrict",
                identity_id=existing.case_id,
                action_id=existing.action_id,
                caller=self,
                dry_run=dry_run,
            )
            updated = Action(
                action_id=existing.action_id,
                case_id=existing.case_id,
                playbook_id=existing.playbook_id,
                action_kind=existing.action_kind,
                approval_required=existing.approval_required,
                state=ActionState.rolled_back,
                simulator_ref=sim_ref,
                reason=existing.reason,
                created_at=existing.created_at,
                updated_at=now_iso,
                expires_at=existing.expires_at,
                approved_by=analyst,
            )
            self._persist_action(updated)
            audit.append("a14", "action_rolled_back", {
                "action_id": updated.action_id,
                "case_id": updated.case_id,
                "analyst": analyst,
            })
            state.setdefault("actions", {})[updated.action_id] = updated
            return [ctx.new_message(topic="actions", payload=updated, producer=self.agent_id)]

        return []

    def on_tick(self, state: dict[str, Any], ctx: AgentContext) -> list[Message]:
        now_dt = ctx.clock() if callable(ctx.clock) else ctx.clock.now()
        now_iso = now_dt.isoformat()
        dry_run = getattr(ctx.settings, "dry_run", v3_cfg.DRY_RUN)
        out: list[Message] = []

        actions: dict[str, Action] = state.get("actions", {})
        for act in list(actions.values()):
            # 1. Check approval timeout (pending_approval -> expired)
            if act.state == ActionState.pending_approval:
                is_expired = False
                if act.expires_at:
                    try:
                        exp_dt = datetime.fromisoformat(act.expires_at)
                        if now_dt >= exp_dt:
                            is_expired = True
                    except (ValueError, TypeError) as exc:
                        log.debug("Invalid expires_at datetime on action %s: %s", act.action_id, exc)
                if is_expired:
                    expired_act = Action(
                        action_id=act.action_id,
                        case_id=act.case_id,
                        playbook_id=act.playbook_id,
                        action_kind=act.action_kind,
                        approval_required=act.approval_required,
                        state=ActionState.expired,
                        simulator_ref=act.simulator_ref,
                        reason="Approval timed out after 30 minutes",
                        created_at=act.created_at,
                        updated_at=now_iso,
                        expires_at=act.expires_at,
                        approved_by=act.approved_by,
                    )
                    self._persist_action(expired_act)
                    audit.append("a14", "action_expired", {
                        "action_id": expired_act.action_id,
                        "case_id": expired_act.case_id,
                    })
                    actions[act.action_id] = expired_act
                    out.append(ctx.new_message(topic="actions", payload=expired_act, producer=self.agent_id))

            # 2. Check restrict TTL expiry (applied with TTL -> rolled_back)
            elif act.state == ActionState.applied and act.expires_at:
                is_ttl_expired = False
                try:
                    exp_dt = datetime.fromisoformat(act.expires_at)
                    if now_dt >= exp_dt:
                        is_ttl_expired = True
                except (ValueError, TypeError) as exc:
                    log.debug("Invalid expires_at datetime on action %s: %s", act.action_id, exc)
                if is_ttl_expired:
                    sim_ref = self._sim_client.rollback(
                        rollback_action="revert_restrict",
                        identity_id=act.case_id,
                        action_id=act.action_id,
                        caller=self,
                        dry_run=dry_run,
                    )
                    rb_act = Action(
                        action_id=act.action_id,
                        case_id=act.case_id,
                        playbook_id=act.playbook_id,
                        action_kind=act.action_kind,
                        approval_required=act.approval_required,
                        state=ActionState.rolled_back,
                        simulator_ref=sim_ref,
                        reason="Restrict TTL expired; automatically rolled back",
                        created_at=act.created_at,
                        updated_at=now_iso,
                        expires_at=act.expires_at,
                        approved_by="system",
                    )
                    self._persist_action(rb_act)
                    audit.append("a14", "action_rolled_back", {
                        "action_id": rb_act.action_id,
                        "case_id": rb_act.case_id,
                        "reason": "ttl_expired",
                    })
                    actions[act.action_id] = rb_act
                    out.append(ctx.new_message(topic="actions", payload=rb_act, producer=self.agent_id))

        return out
