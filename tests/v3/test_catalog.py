"""Unit tests for app/v3/catalog.py event catalog and lookups."""
import pytest

from app.v3.catalog import lookup
from app.v3.models import ActionType, EventClass, Source, Stage

REQUIRED_OKTA_ACTIONS = [
    "user.session.start",
    "user.authentication.sso",
    "user.authentication.auth_via_mfa",
    "user.authentication.verify",
    "user.mfa.okta_verify.deny_push",
    "system.push.send_factor_verify_push",
    "user.account.lock",
    "user.session.end",
    "policy.evaluate_sign_on",
]

REQUIRED_CLOUDTRAIL_ACTIONS = [
    "ConsoleLogin",
    "AssumeRole",
    "AssumeRoleWithSAML",
    "GetSessionToken",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "CreateUser",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AddUserToGroup",
    "UpdateAssumeRolePolicy",
    "PassRole",
    "CreateFunction",
    "UpdateFunctionCode",
    "Invoke",
    "ListUsers",
    "ListRoles",
    "ListBuckets",
    "ListPolicies",
    "GetAccountAuthorizationDetails",
    "DescribeInstances",
    "GetSecretValue",
    "ListSecrets",
    "GetObject",
    "PutObject",
    "DeleteObject",
    "PutBucketPolicy",
    "PutBucketAcl",
    "DeletePublicAccessBlock",
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteDetector",
    "UpdateDetector",
    "DisassociateMembers",
    "DeleteFlowLogs",
    "ScheduleKeyDeletion",
    "DisableKey",
    "Decrypt",
]


@pytest.mark.parametrize("action", REQUIRED_OKTA_ACTIONS)
def test_okta_catalog_coverage(action: str) -> None:
    entry = lookup(Source.okta, action)
    assert not entry.uncatalogued
    assert entry.event_class is not None
    assert entry.action_type is not None


@pytest.mark.parametrize("action", REQUIRED_CLOUDTRAIL_ACTIONS)
def test_cloudtrail_catalog_coverage(action: str) -> None:
    entry = lookup("cloudtrail", action)
    assert not entry.uncatalogued
    assert entry.event_class is not None
    assert entry.action_type is not None


def test_unknown_action_defaults() -> None:
    entry_read = lookup("cloudtrail", "DescribeCustomResource")
    assert entry_read.uncatalogued is True
    assert entry_read.read_only is True
    assert entry_read.action_type == ActionType.read

    entry_write = lookup("cloudtrail", "ModifyCustomCluster")
    assert entry_write.uncatalogued is True
    assert entry_write.read_only is False
    assert entry_write.action_type == ActionType.write


def test_specific_mitre_and_classification() -> None:
    stop_log = lookup("cloudtrail", "StopLogging")
    assert "T1562.008" in stop_log.mitre
    assert stop_log.action_type == ActionType.defense_evasion
    assert stop_log.stage_hint == Stage.defense_evasion
    assert not stop_log.read_only

    get_sec = lookup("cloudtrail", "GetSecretValue")
    assert "T1555.006" in get_sec.mitre
    assert get_sec.event_class == EventClass.data_access
    assert get_sec.read_only is True

    attach_pol = lookup("cloudtrail", "AttachUserPolicy")
    assert "T1098" in attach_pol.mitre
    assert attach_pol.action_type == ActionType.permission_change
    assert attach_pol.stage_hint == Stage.privilege_escalation

    deny_push = lookup("okta", "user.mfa.okta_verify.deny_push")
    assert "T1621" in deny_push.mitre
    assert deny_push.stage_hint == Stage.credential_access
