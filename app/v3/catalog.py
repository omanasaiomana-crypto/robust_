"""Event classification and action catalog for IdentityShield v3.

Maps (source, action) to (event_class, action_type, stage_hint, mitre, read_only).
Unknown actions fall back to default entries with uncatalogued=True.
"""
from dataclasses import dataclass

from app.v3.models import ActionType, EventClass, Source, Stage


@dataclass(frozen=True)
class CatalogEntry:
    """Catalog metadata for a log event."""

    event_class: EventClass
    action_type: ActionType
    stage_hint: Stage
    mitre: list[str]
    read_only: bool
    uncatalogued: bool = False


# ---------------------------------------------------------------------------
# Catalog Table: (source_str, action_name) -> CatalogEntry
# ---------------------------------------------------------------------------

CATALOG: dict[tuple[str, str], CatalogEntry] = {
    # --- Okta Events ---
    ("okta", "user.session.start"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=["T1078.004"],
        read_only=True,
    ),
    ("okta", "user.authentication.sso"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=["T1078"],
        read_only=True,
    ),
    ("okta", "user.authentication.auth_via_mfa"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=["T1078"],
        read_only=True,
    ),
    ("okta", "user.authentication.verify"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=["T1078"],
        read_only=True,
    ),
    ("okta", "user.mfa.okta_verify.deny_push"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.credential_access,
        mitre=["T1621"],
        read_only=True,
    ),
    ("okta", "system.push.send_factor_verify_push"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.credential_access,
        mitre=["T1621"],
        read_only=True,
    ),
    ("okta", "user.account.lock"): CatalogEntry(
        event_class=EventClass.account_change,
        action_type=ActionType.write,
        stage_hint=Stage.impact,
        mitre=["T1531"],
        read_only=False,
    ),
    ("okta", "user.session.end"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=[],
        read_only=True,
    ),
    ("okta", "policy.evaluate_sign_on"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=["T1078"],
        read_only=True,
    ),
    # --- AWS CloudTrail Events ---
    ("cloudtrail", "ConsoleLogin"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.initial_access,
        mitre=["T1078"],
        read_only=True,
    ),
    ("cloudtrail", "AssumeRole"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1548"],
        read_only=True,
    ),
    ("cloudtrail", "AssumeRoleWithSAML"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1548"],
        read_only=True,
    ),
    ("cloudtrail", "GetSessionToken"): CatalogEntry(
        event_class=EventClass.authentication,
        action_type=ActionType.read,
        stage_hint=Stage.credential_access,
        mitre=["T1550"],
        read_only=True,
    ),
    ("cloudtrail", "CreateAccessKey"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.credential_change,
        stage_hint=Stage.persistence,
        mitre=["T1098.001"],
        read_only=False,
    ),
    ("cloudtrail", "DeleteAccessKey"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.destructive,
        stage_hint=Stage.impact,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "UpdateAccessKey"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.credential_change,
        stage_hint=Stage.persistence,
        mitre=["T1098.001"],
        read_only=False,
    ),
    ("cloudtrail", "CreateUser"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.write,
        stage_hint=Stage.persistence,
        mitre=["T1136.003"],
        read_only=False,
    ),
    ("cloudtrail", "CreateLoginProfile"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.credential_change,
        stage_hint=Stage.persistence,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "UpdateLoginProfile"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.credential_change,
        stage_hint=Stage.persistence,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "AttachUserPolicy"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "AttachRolePolicy"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "PutUserPolicy"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "PutRolePolicy"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "CreatePolicyVersion"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "SetDefaultPolicyVersion"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "AddUserToGroup"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098"],
        read_only=False,
    ),
    ("cloudtrail", "UpdateAssumeRolePolicy"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1098", "T1548"],
        read_only=False,
    ),
    ("cloudtrail", "PassRole"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1548"],
        read_only=False,
    ),
    ("cloudtrail", "CreateFunction"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.write,
        stage_hint=Stage.persistence,
        mitre=["T1548"],
        read_only=False,
    ),
    ("cloudtrail", "UpdateFunctionCode"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.write,
        stage_hint=Stage.persistence,
        mitre=["T1548"],
        read_only=False,
    ),
    ("cloudtrail", "Invoke"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.write,
        stage_hint=Stage.privilege_escalation,
        mitre=["T1548"],
        read_only=False,
    ),
    ("cloudtrail", "ListUsers"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1087.004"],
        read_only=True,
    ),
    ("cloudtrail", "ListRoles"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1087.004"],
        read_only=True,
    ),
    ("cloudtrail", "ListBuckets"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1526"],
        read_only=True,
    ),
    ("cloudtrail", "ListPolicies"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1087.004"],
        read_only=True,
    ),
    ("cloudtrail", "GetAccountAuthorizationDetails"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1087.004"],
        read_only=True,
    ),
    ("cloudtrail", "DescribeInstances"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1526"],
        read_only=True,
    ),
    ("cloudtrail", "GetSecretValue"): CatalogEntry(
        event_class=EventClass.data_access,
        action_type=ActionType.read,
        stage_hint=Stage.credential_access,
        mitre=["T1555.006"],
        read_only=True,
    ),
    ("cloudtrail", "ListSecrets"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read,
        stage_hint=Stage.discovery,
        mitre=["T1526"],
        read_only=True,
    ),
    ("cloudtrail", "GetObject"): CatalogEntry(
        event_class=EventClass.data_access,
        action_type=ActionType.read,
        stage_hint=Stage.collection,
        mitre=["T1530"],
        read_only=True,
    ),
    ("cloudtrail", "PutObject"): CatalogEntry(
        event_class=EventClass.data_access,
        action_type=ActionType.write,
        stage_hint=Stage.collection,
        mitre=["T1530"],
        read_only=False,
    ),
    ("cloudtrail", "DeleteObject"): CatalogEntry(
        event_class=EventClass.data_access,
        action_type=ActionType.destructive,
        stage_hint=Stage.impact,
        mitre=["T1485"],
        read_only=False,
    ),
    ("cloudtrail", "PutBucketPolicy"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.defense_evasion,
        mitre=["T1530"],
        read_only=False,
    ),
    ("cloudtrail", "PutBucketAcl"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.permission_change,
        stage_hint=Stage.defense_evasion,
        mitre=["T1530"],
        read_only=False,
    ),
    ("cloudtrail", "DeletePublicAccessBlock"): CatalogEntry(
        event_class=EventClass.entity_management,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1530", "T1562"],
        read_only=False,
    ),
    ("cloudtrail", "StopLogging"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.008"],
        read_only=False,
    ),
    ("cloudtrail", "DeleteTrail"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.008"],
        read_only=False,
    ),
    ("cloudtrail", "UpdateTrail"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.008"],
        read_only=False,
    ),
    ("cloudtrail", "PutEventSelectors"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.008"],
        read_only=False,
    ),
    ("cloudtrail", "DeleteDetector"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.001"],
        read_only=False,
    ),
    ("cloudtrail", "UpdateDetector"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.001"],
        read_only=False,
    ),
    ("cloudtrail", "DisassociateMembers"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.001"],
        read_only=False,
    ),
    ("cloudtrail", "DeleteFlowLogs"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.defense_evasion,
        stage_hint=Stage.defense_evasion,
        mitre=["T1562.008"],
        read_only=False,
    ),
    ("cloudtrail", "ScheduleKeyDeletion"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.destructive,
        stage_hint=Stage.impact,
        mitre=["T1485"],
        read_only=False,
    ),
    ("cloudtrail", "DisableKey"): CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.destructive,
        stage_hint=Stage.impact,
        mitre=["T1485"],
        read_only=False,
    ),
    ("cloudtrail", "Decrypt"): CatalogEntry(
        event_class=EventClass.data_access,
        action_type=ActionType.read,
        stage_hint=Stage.credential_access,
        mitre=["T1555"],
        read_only=True,
    ),
}


def lookup(source: str | Source, action: str) -> CatalogEntry:
    """Look up an event action in the catalog.

    Returns catalog entry if known; otherwise returns default uncatalogued entry.
    """
    src_key = source.value if isinstance(source, Source) else str(source).lower()
    key = (src_key, action)
    if key in CATALOG:
        return CATALOG[key]

    # Heuristic for unknown / uncatalogued actions
    is_ro = action.startswith(("Get", "List", "Describe", "Head", "View", "Check", "Read"))
    return CatalogEntry(
        event_class=EventClass.api_activity,
        action_type=ActionType.read if is_ro else ActionType.write,
        stage_hint=Stage.discovery if is_ro else Stage.initial_access,
        mitre=[],
        read_only=is_ro,
        uncatalogued=True,
    )
