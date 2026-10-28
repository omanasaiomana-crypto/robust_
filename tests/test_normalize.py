"""Unit tests for CloudTrail and Okta log normalization in app/ingest/normalize.py."""
from app.ingest.normalize import (
    canonical_identity,
    normalize_all,
    normalize_cloudtrail,
    normalize_okta,
)
from app.models import Category, Event, Source


def test_canonical_identity():
    assert canonical_identity("alice@example.com") == "alice"
    assert canonical_identity("arn:aws:iam::123456789012:user/bob") == "bob"
    assert canonical_identity("Charlie") == "charlie"
    assert canonical_identity(None) == "unknown"
    assert canonical_identity("") == "unknown"
    assert canonical_identity("   ") == "unknown"


def test_normalize_cloudtrail():
    raw_ct = {
        "eventID": "ct-test-01",
        "eventTime": "2026-10-28T10:15:30Z",
        "eventName": "DescribeInstances",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "alice@corp.com",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        },
        "sourceIPAddress": "198.51.100.24",
        "userAgent": "aws-cli/2.15.0",
        "awsRegion": "us-east-1",
        "requestParameters": {"filter": []},
        "label": "benign",
    }
    evt = normalize_cloudtrail(raw_ct, 1)
    assert evt is not None
    assert isinstance(evt, Event)
    assert evt.event_id == "ct-test-01"
    assert evt.source == Source.cloudtrail
    assert evt.identity_id == "alice"
    assert evt.action == "DescribeInstances"
    assert evt.category == Category.api
    assert evt.outcome == "success"
    assert evt.src_ip == "198.51.100.24"
    assert evt.token_id == "AKIAIOSFODNN7EXAMPLE"
    assert evt.region == "us-east-1"
    assert evt.label == "benign"


def test_normalize_okta():
    raw_okta = {
        "uuid": "okta-test-01",
        "published": "2026-10-28T10:14:00Z",
        "eventType": "user.session.start",
        "actor": {
            "id": "00u123456",
            "alternateId": "bob.smith@corp.com",
        },
        "client": {
            "ipAddress": "203.0.113.50",
            "geographicalContext": {
                "city": "Bengaluru",
                "country": "India",
                "geolocation": {"lat": 12.9716, "lon": 77.5946},
            },
            "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/126.0"},
            "device": "device-fingerprint-abc",
        },
        "authenticationContext": {
            "externalSessionId": "sess-okta-999",
        },
        "outcome": {"result": "SUCCESS"},
        "securityContext": {"asNumber": 9498},
        "label": "benign",
    }
    evt = normalize_okta(raw_okta, 1)
    assert evt is not None
    assert isinstance(evt, Event)
    assert evt.event_id == "okta-test-01"
    assert evt.source == Source.okta
    assert evt.identity_id == "bob.smith"
    assert evt.session_id == "sess-okta-999"
    assert evt.action == "user.session.start"
    assert evt.category == Category.auth
    assert evt.outcome == "success"
    assert evt.city == "Bengaluru"
    assert evt.country == "India"
    assert evt.lat == 12.9716
    assert evt.lon == 77.5946
    assert evt.asn == "9498"
    assert evt.device_id == "device-fingerprint-abc"


def test_missing_fields_defaults():
    # CloudTrail with minimal fields
    minimal_ct = {
        "eventTime": "2026-10-28T12:00:00Z",
    }
    evt_ct = normalize_cloudtrail(minimal_ct, 99)
    assert evt_ct is not None
    assert evt_ct.identity_id == "unknown"
    assert evt_ct.action == "Unknown"
    assert evt_ct.outcome == "success"
    assert evt_ct.resource_sensitivity == 1
    assert evt_ct.privilege_level == 1

    # Okta with minimal fields
    minimal_okta = {
        "published": "2026-10-28T12:00:00Z",
    }
    evt_okta = normalize_okta(minimal_okta, 99)
    assert evt_okta is not None
    assert evt_okta.identity_id == "unknown"
    assert evt_okta.action == "unknown"
    assert evt_okta.category == Category.api
    assert evt_okta.outcome == "success"


def test_bad_records_skipped():
    # Missing timestamp in CT
    bad_ct = {"eventName": "Test", "sourceIPAddress": "1.2.3.4"}
    assert normalize_cloudtrail(bad_ct, 1) is None

    # Invalid timestamp in Okta
    bad_okta = {"published": "not-a-valid-date", "eventType": "user.session.start"}
    assert normalize_okta(bad_okta, 1) is None

    # normalize_all should skip bad records and count them
    valid_ct = {"eventTime": "2026-10-28T10:00:00Z", "eventName": "ValidEvent"}
    df, skipped = normalize_all([bad_ct, valid_ct], [bad_okta])
    assert skipped == 2
    assert len(df) == 1
    assert df.iloc[0]["action"] == "ValidEvent"
