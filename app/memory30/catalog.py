"""Action categories and attack stages used by the 30-day memory."""
from __future__ import annotations

# ---- categories ---------------------------------------------------------------------------------
LOGIN = "login"
LOGIN_FAIL = "login_fail"
MFA_DENY = "mfa_deny"
MFA_CHANGE = "mfa_change"
CREDENTIAL = "credential"
DISCOVERY = "discovery"
PRIVESC = "privesc"
DATA_READ = "data_read"
DATA_WRITE = "data_write"
EXFIL_SHARE = "exfil_share"
DEFENSE_EVASION = "defense_evasion"
OTHER_READ = "other_read"
OTHER_WRITE = "other_write"

CT_LOGIN = {"ConsoleLogin", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}
CT_MFA_CHANGE = {"CreateVirtualMFADevice", "EnableMFADevice", "DeactivateMFADevice", "DeleteVirtualMFADevice",
                 "ResyncMFADevice"}
CT_CREDENTIAL = {"CreateAccessKey", "UpdateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
                 "CreateServiceSpecificCredential", "UploadSSHPublicKey", "ChangePassword"}
CT_PRIVESC = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy",
              "PutGroupPolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion", "AddUserToGroup",
              "UpdateAssumeRolePolicy", "PassRole", "CreateRole", "CreateUser"}
CT_DATA_READ = {"GetObject", "GetSecretValue", "BatchGetSecretValue", "Decrypt", "GetParameter", "GetParameters",
                "GetParametersByPath", "SelectObjectContent", "DownloadDBLogFilePortion", "Sign"}
CT_DATA_WRITE = {"PutObject", "DeleteObject", "DeleteObjects", "CopyObject", "UpdateFunctionCode",
                 "PutParameter", "UpdateSecret", "PutSecretValue", "RegisterTaskDefinition", "UpdateService"}
CT_EXFIL_SHARE = {"ModifySnapshotAttribute", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute",
                  "PutBucketPolicy", "PutBucketAcl", "PutBucketReplication", "DeletePublicAccessBlock",
                  "PutObjectAcl", "ModifyImageAttribute", "SharePortfolio"}
CT_DEFENSE_EVASION = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector",
                      "UpdateDetector", "DisassociateMembers", "DeleteFlowLogs", "DisableKey",
                      "ScheduleKeyDeletion", "DeleteConfigRule", "StopConfigurationRecorder"}
CT_DISCOVERY_EXTRA = {"GetAccountAuthorizationDetails", "GetBucketPolicy", "GetBucketAcl", "GetPolicy",
                      "GetPolicyVersion", "GetRolePolicy", "GetUserPolicy", "GetCallerIdentity",
                      "GetBucketLocation", "SearchResources"}


def categorize(source: str, action: str, outcome: str) -> str:
    """Map a normalized event to one category. Pure function."""
    a = action or ""
    if source == "okta":
        low = a.lower()
        if "deny_push" in low or "mfa.okta_verify.deny" in low:
            return MFA_DENY
        if ("factor" in low and any(k in low for k in ("activate", "enroll", "reset", "update", "deactivate"))) \
                or "user.mfa.factor" in low:
            return MFA_CHANGE
        if "reset_password" in low or "password.update" in low or "credential" in low:
            return CREDENTIAL
        if low.startswith("user.session.start") or low.startswith("user.authentication"):
            return LOGIN_FAIL if outcome == "failure" else LOGIN
        if "privilege.grant" in low or "group.user_membership.add" in low or "app.user_membership.add" in low:
            return PRIVESC
        return OTHER_READ
    if a in CT_LOGIN:
        return LOGIN_FAIL if outcome == "failure" else LOGIN
    if a in CT_MFA_CHANGE:
        return MFA_CHANGE
    if a in CT_CREDENTIAL:
        return CREDENTIAL
    if a in CT_PRIVESC:
        return PRIVESC
    if a in CT_EXFIL_SHARE:
        return EXFIL_SHARE
    if a in CT_DEFENSE_EVASION:
        return DEFENSE_EVASION
    if a in CT_DATA_READ:
        return DATA_READ
    if a in CT_DATA_WRITE:
        return DATA_WRITE
    if a in CT_DISCOVERY_EXTRA or a.startswith(("List", "Describe")):
        return DISCOVERY
    if a.startswith(("Get", "Head", "Lookup", "Search")):
        return OTHER_READ
    return OTHER_WRITE


# ---- attack-stage hits ----------------------------------------------------------------------------
# kind -> (kill-chain stage, severity 0..1, plain-English label)
HIT_KINDS: dict[str, tuple[str, float, str]] = {
    "new_network": ("initial_access", 0.35, "activity from a network never used by this identity"),
    "proxy_login": ("initial_access", 0.50, "login through a proxy / anonymizing network"),
    "mfa_change": ("persistence", 0.60, "MFA device registration or change"),
    "credential": ("persistence", 0.50, "new credentials created (access key, password, login profile)"),
    "discovery": ("discovery", 0.25, "burst of discovery calls across services"),
    "privesc": ("privilege_escalation", 0.70, "permissions or roles granted"),
    "read_staircase": ("collection", 0.40, "sensitive data reads growing week over week"),
    "modify_sensitive": ("impact", 0.70, "change to a sensitive / production resource"),
    "exfil_share": ("exfiltration", 0.80, "data or snapshot shared outside / made public"),
    "defense_evasion": ("defense_evasion", 0.80, "logging or detection disabled"),
}

STAGE_ORDER = ["initial_access", "persistence", "discovery", "privilege_escalation", "collection",
               "defense_evasion", "impact", "exfiltration"]

# category -> hit kind for per-event hits (others are computed per day / per week)
CATEGORY_HIT = {
    MFA_CHANGE: "mfa_change",
    CREDENTIAL: "credential",
    PRIVESC: "privesc",
    EXFIL_SHARE: "exfil_share",
    DEFENSE_EVASION: "defense_evasion",
}
