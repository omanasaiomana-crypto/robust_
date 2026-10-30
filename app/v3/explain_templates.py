"""Plain English explanation templates for all detection IDs.

Follows context.md Section 13 and PRD §15.2.
Values are safely formatted from signal details; HTML escaping is applied by the UI.
"""
from __future__ import annotations

from typing import Any

# Templates for every frozen detection ID in v3
EXPLAIN_TEMPLATES: dict[str, str] = {
    # 13.1 Access Anomalies
    "D-ACC-01": "Impossible travel between {prev_city} and {city} ({implied_speed_kmh} km/h over {distance_km} km).",
    "D-ACC-02": "Access from a new device or ASN ({asn}) not observed in recent history.",
    "D-ACC-03": "Activity at an unusual hour ({hour}:00 UTC) outside typical active hours.",
    "D-ACC-04": "Authentication via anonymizing network or Tor exit node ({src_ip}) on privileged identity.",

    # 13.1 Session Integrity
    "D-SES-01": "Token replay: session used from new ASN ({asn}) without re-authentication.",
    "D-SES-02": "MFA fatigue: repeated push denials ({denies}) followed by rapid approval.",
    "D-SES-03": "Browser fingerprint drift detected across consecutive requests in session.",
    "D-SES-04": "Privileged cloud session established without multi-factor authentication (MFA).",

    # 13.2 Credentials
    "D-CRD-01": "Dormant account inactive for {dormant_days} days suddenly became active.",
    "D-CRD-02": "IAM access key created for another user account ({target_user}).",
    "D-CRD-03": "New IAM access key used from an unfamiliar location or IP ({src_ip}).",
    "D-CRD-04": "EC2 instance role credential used from external IP ({src_ip}) outside AWS.",
    "D-CRD-05": "Login profile or console password modified for another user ({target_user}).",

    # 13.3 Defense Evasion & Impact
    "D-DEF-01": "CloudTrail logging stopped or trail deleted ({trail_name}) to evade monitoring.",
    "D-DEF-02": "AWS GuardDuty detector ({detector_id}) disabled or disassociated.",
    "D-DEF-03": "VPC flow logs deleted ({flow_log_id}) impairing network security auditing.",
    "D-DEF-04": "Resource ACL or policy updated to allow public exposure ({resource_name}).",
    "D-DEF-05": "KMS cryptographic key ({key_id}) scheduled for deletion or disabled.",
    "D-DEF-06": "Mass deletion anomaly: {deleted_count} cloud resources destroyed within {window_minutes} min.",
    "D-DEF-07": "Secret harvesting: {accessed_count} sensitive secrets accessed in Secrets Manager / SSM.",

    # 13.4 Privilege Escalation Paths
    "D-PE-01": "IAM policy version created and set as default to expand privileges.",
    "PE-01": "IAM policy version created and set as default to expand privileges.",
    "D-PE-02": "Administrative policy ({policy_name}) attached to user followed by privileged actions.",
    "PE-02": "Administrative policy ({policy_name}) attached to user followed by privileged actions.",
    "D-PE-03": "Inline policy with wildcard permissions attached to user or role.",
    "PE-03": "Inline policy with wildcard permissions attached to user or role.",
    "D-PE-04": "IAM role passed to Lambda function followed by invocation.",
    "PE-04": "IAM role passed to Lambda function followed by invocation.",
    "D-PE-05": "AssumeRole trust policy modified followed by privileged role assumption.",
    "PE-05": "AssumeRole trust policy modified followed by privileged role assumption.",
    "D-PE-06": "User added to privileged administrative group ({group_name}).",
    "PE-06": "User added to privileged administrative group ({group_name}).",
    "D-PE-07": "Credentials created for another account followed by activity impersonation.",
    "PE-07": "Credentials created for another account followed by activity impersonation.",
    "D-PE-08": "Full attack chain: reconnaissance discovery burst leading to privilege escalation and data access.",
    "PE-08": "Full attack chain: reconnaissance discovery burst leading to privilege escalation and data access.",

    # 13.5 Behavioral ML
    "D-ML-01": "Unusual session profile: Isolation Forest anomaly ranked in top percentile ({percentile}).",
    "D-ML-02": "Rarified action sequence: Markov sequence rarity ranked in top percentile ({percentile}).",

    # 13.6 Campaigns
    "D-CMP-01": "Password spray attack against {unique_targets} identities from {source}.",
    "D-CMP-02": "Credential stuffing success on targeted identity following previous spray.",
    "D-CMP-03": "Shared threat infrastructure ({source}) active across {identity_count} identities.",
}


class _SafeFormatDict(dict):
    """Dictionary that returns placeholder name in brackets if missing."""

    def __missing__(self, key: str) -> str:
        return f"<{key}>"


def render_reason(detection_id: str, details: dict[str, Any] | None = None, summary: str = "") -> str:
    """Render a concise, human-readable reason string from template and signal details.

    Falls back to signal summary or detection ID if template is missing.
    """
    details = details or {}
    det_id = str(detection_id or "").strip()

    template = EXPLAIN_TEMPLATES.get(det_id)
    if not template:
        # Check without D- prefix or with D- prefix
        if det_id.startswith("D-"):
            template = EXPLAIN_TEMPLATES.get(det_id[2:])
        else:
            template = EXPLAIN_TEMPLATES.get(f"D-{det_id}")

    if not template:
        return summary or f"Suspicious activity flagged by detector {det_id}."

    # Format cleanly with details
    clean_details: dict[str, Any] = {}
    for k, v in details.items():
        if isinstance(v, float):
            clean_details[k] = f"{v:.1f}"
        else:
            clean_details[k] = str(v)

    # Provide common fallback keys so missing placeholders don't look raw
    clean_details.setdefault("prev_city", "prior location")
    clean_details.setdefault("city", "new location")
    clean_details.setdefault("implied_speed_kmh", "excessive")
    clean_details.setdefault("distance_km", "distant")
    clean_details.setdefault("asn", "unfamiliar ASN")
    clean_details.setdefault("hour", "off-hours")
    clean_details.setdefault("src_ip", "external IP")
    clean_details.setdefault("denies", "multiple")
    clean_details.setdefault("dormant_days", "30+")
    clean_details.setdefault("target_user", "target user")
    clean_details.setdefault("trail_name", "trail")
    clean_details.setdefault("detector_id", "detector")
    clean_details.setdefault("flow_log_id", "flow log")
    clean_details.setdefault("resource_name", "cloud resource")
    clean_details.setdefault("key_id", "KMS key")
    clean_details.setdefault("deleted_count", "50+")
    clean_details.setdefault("window_minutes", "5")
    clean_details.setdefault("accessed_count", "multiple")
    clean_details.setdefault("policy_name", "administrative policy")
    clean_details.setdefault("group_name", "admin group")
    clean_details.setdefault("percentile", "99%")
    clean_details.setdefault("unique_targets", "multiple")
    clean_details.setdefault("source", "external source")
    clean_details.setdefault("identity_count", "multiple")

    try:
        return template.format_map(_SafeFormatDict(clean_details))
    except (KeyError, ValueError, TypeError, IndexError):
        return summary or template
