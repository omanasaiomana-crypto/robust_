"""Synthetic 30-day Okta + CloudTrail data with hidden slow attacks and ground-truth labels.

SYNTHETIC DATA: used only to test long-range memory. Never use it for the official KPIs.
Scenarios (inserted when the period is long enough):
  slow_escalation   (needs >= 19 days)  proxy login -> new access key -> discovery burst -> admin policy, 14 days
  slow_heist        (needs >= 22 days)  VPN session + MFA device attempt -> 12 days of discovery -> prod JS change
  insider_staircase (needs >= 29 days)  finance reads growing weekly for 4 weeks -> snapshot shared externally
  gap_31_days       (needs >= 34 days)  two risky steps 32 days apart: must NOT be linked
"""
from __future__ import annotations

import json
import random
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ACCOUNT = "111122223333"
EXTERNAL_ACCOUNT = "999988887777"
TEAMS = ["engineering", "finance", "sales", "ops", "data"]
OFFICE_ASN = 64500
PROXY_IP, PROXY_ASN = "185.220.101.23", 64510
VPN_IP = "45.137.21.9"


class _Gen:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.okta: list[dict] = []
        self.ct: list[dict] = []

    def _uuid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    @staticmethod
    def _ts(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"

    def okta_login(self, email: str, dt: datetime, ip: str, asn: int, country: str, city: str,
                   proxy: bool = False, event_type: str = "user.session.start", result: str = "SUCCESS") -> str:
        eid = self._uuid()
        self.okta.append({
            "uuid": eid, "published": self._ts(dt), "eventType": event_type,
            "displayMessage": "User login to Okta",
            "actor": {"id": "00u" + email.split("@")[0].replace(".", "")[:12], "type": "User", "alternateId": email},
            "client": {"ipAddress": ip, "userAgent": {"rawUserAgent": "Mozilla/5.0", "os": "Windows",
                                                      "browser": "CHROME"},
                       "geographicalContext": {"country": country, "city": city}},
            "securityContext": {"asNumber": asn, "asOrg": "AS" + str(asn), "isProxy": proxy},
            "authenticationContext": {"externalSessionId": "idx" + eid[:12]},
            "outcome": {"result": result},
        })
        return f"okta:{eid}"

    def ct_event(self, email: str, team: str, dt: datetime, name: str, source: str, ip: str,
                 params: dict | None = None, error: str | None = None, saml: bool = False) -> str:
        eid = self._uuid()
        if saml:
            ui = {"type": "SAMLUser", "principalId": f"okta:{email}", "userName": email}
        else:
            ui = {"type": "AssumedRole", "principalId": f"AROAEXAMPLE{team.upper()}:{email}",
                  "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{team}-role/{email}",
                  "accountId": ACCOUNT, "accessKeyId": "ASIA" + eid.replace("-", "")[:16].upper(),
                  "sessionContext": {"sessionIssuer": {"type": "Role", "userName": f"{team}-role",
                                                       "arn": f"arn:aws:iam::{ACCOUNT}:role/{team}-role"}}}
        rec = {
            "eventVersion": "1.09", "eventID": eid, "eventTime": self._ts(dt).split(".")[0] + "Z",
            "eventSource": f"{source}.amazonaws.com", "eventName": name, "awsRegion": "ap-south-1",
            "sourceIPAddress": ip, "userAgent": "aws-cli/2.15.0", "userIdentity": ui,
            "requestParameters": params or {}, "recipientAccountId": ACCOUNT,
            "readOnly": name.startswith(("Get", "List", "Describe")),
            "managementEvent": source not in ("s3",) or name not in ("GetObject", "PutObject"),
        }
        if error:
            rec["errorCode"] = error
            rec["errorMessage"] = "User is not authorized to perform this operation"
        self.ct.append(rec)
        return f"cloudtrail:{eid}"


def _profiles(n: int, rng: random.Random) -> list[dict]:
    first = ["arun", "divya", "kiran", "neha", "rahul", "sneha", "vikram", "pooja", "anil", "isha", "manoj", "priya"]
    out = []
    for i in range(n):
        team = TEAMS[i % len(TEAMS)]
        name = f"{first[i % len(first)]}{i:03d}"
        out.append({
            "email": f"{name}@acme.example", "team": team,
            "office_ip": f"198.51.100.{(i % 250) + 1}",
            "home_ip": f"203.0.{113 + (i % 10)}.{(i * 7) % 250 + 1}", "home_asn": 64501 + (i % 5),
            "home_ratio": rng.choice([0.0, 0.1, 0.2, 0.3]),
            "start_hour": rng.choice([3, 4, 5]),  # UTC (about 08:30-10:30 IST)
        })
    for email in ("ravi.dev@acme.example", "safe.dev@acme.example", "meera.ops@acme.example",
                  "old.ops@acme.example"):
        out.append({"email": email, "team": "engineering", "office_ip": "198.51.100.200",
                    "home_ip": "203.0.120.77", "home_asn": 64503, "home_ratio": 0.0, "start_hour": 4})
    return out


def _normal_day(g: _Gen, p: dict, day: date) -> None:
    rng = g.rng
    at_home = rng.random() < p["home_ratio"]
    ip = p["home_ip"] if at_home else p["office_ip"]
    asn = p["home_asn"] if at_home else OFFICE_ASN
    t = datetime(day.year, day.month, day.day, p["start_hour"], rng.randint(0, 59), rng.randint(0, 59),
                 tzinfo=timezone.utc)
    g.okta_login(p["email"], t, ip, asn, "India", "Bengaluru")
    t += timedelta(seconds=rng.randint(20, 90))
    g.ct_event(p["email"], p["team"], t, "AssumeRoleWithSAML", "sts", ip,
               {"roleArn": f"arn:aws:iam::{ACCOUNT}:role/{p['team']}-role"}, saml=True)
    team = p["team"]
    for _ in range(rng.randint(4, 12)):
        t += timedelta(minutes=rng.randint(3, 40))
        r = rng.random()
        if team == "finance" and r < 0.45:
            g.ct_event(p["email"], team, t, "GetObject", "s3", ip,
                       {"bucketName": "acme-finance-reports", "key": f"q3/report-{rng.randint(1, 40)}.xlsx"})
        elif r < 0.65:
            g.ct_event(p["email"], team, t, "GetObject", "s3", ip,
                       {"bucketName": f"acme-{team}-shared", "key": f"docs/file-{rng.randint(1, 200)}.pdf"})
        elif r < 0.82:
            g.ct_event(p["email"], team, t, "PutObject", "s3", ip,
                       {"bucketName": f"acme-{team}-shared", "key": f"docs/file-{rng.randint(1, 200)}.pdf"})
        elif r < 0.90:
            g.ct_event(p["email"], team, t, "ListBuckets", "s3", ip)
        elif team == "engineering" and r < 0.97:
            g.ct_event(p["email"], team, t, "DescribeInstances", "ec2", ip)
        else:
            g.ct_event(p["email"], team, t, "GetCallerIdentity", "sts", ip)


def generate(days: int = 30, identities: int = 50, seed: int = 42, end: date | None = None) -> tuple[list, list, dict]:
    days = max(7, min(int(days), 120))
    g = _Gen(seed)
    end = end or datetime.now(timezone.utc).date()
    start = end - timedelta(days=days - 1)
    profiles = _profiles(max(5, int(identities)), g.rng)
    by_email = {p["email"]: p for p in profiles}
    labels: dict = {"synthetic": True, "start": start.isoformat(), "end": end.isoformat(), "days": days,
                    "identities": len(profiles), "scenarios": []}

    for i in range(days):
        day = start + timedelta(days=i)
        weekend = day.weekday() >= 5
        for p in profiles:
            forced = p["email"] == "meera.ops@acme.example" and i == days - 1
            if forced or g.rng.random() < (0.15 if weekend else 0.9):
                _normal_day(g, p, day)

    def at(day_index: int, hour: int, minute: int = 0) -> datetime:
        d = start + timedelta(days=day_index)
        return datetime(d.year, d.month, d.day, hour, minute, tzinfo=timezone.utc)

    # ---- 1. slow escalation over 14 days
    if days >= 19:
        p = by_email["ravi.dev@acme.example"]
        d0 = days - 16
        ids = [g.okta_login(p["email"], at(d0, 21, 5), PROXY_IP, PROXY_ASN, "Netherlands", "Amsterdam", proxy=True)]
        ids.append(g.ct_event(p["email"], "engineering", at(d0, 21, 9), "ListBuckets", "s3", PROXY_IP))
        ids.append(g.ct_event(p["email"], "engineering", at(d0 + 5, 22, 0), "CreateAccessKey", "iam", PROXY_IP,
                              {"userName": "ravi.dev"}))
        for k, (name, src) in enumerate([("ListUsers", "iam"), ("ListRoles", "iam"), ("ListPolicies", "iam"),
                                         ("GetAccountAuthorizationDetails", "iam"), ("ListBuckets", "s3"),
                                         ("DescribeInstances", "ec2"), ("ListSecrets", "secretsmanager")]):
            ids.append(g.ct_event(p["email"], "engineering", at(d0 + 9, 22, k * 3), name, src, PROXY_IP))
        ids.append(g.ct_event(p["email"], "engineering", at(d0 + 14, 22, 30), "AttachUserPolicy", "iam", PROXY_IP,
                              {"userName": "ravi.dev",
                               "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
        ids.append(g.ct_event(p["email"], "engineering", at(d0 + 14, 22, 41), "GetSecretValue", "secretsmanager",
                              PROXY_IP, {"secretId": "acme/prod/db-password"}))
        labels["scenarios"].append({"name": "slow_escalation", "identity": p["email"], "days": 15,
                                    "expected": "linked", "min_stages": 3, "event_ids": ids})

    # ---- 2. slow heist (Bybit-style, inspired by the public timeline)
    if days >= 22:
        p = by_email["safe.dev@acme.example"]
        b0 = days - 19
        ids = [g.ct_event(p["email"], "engineering", at(b0, 20, 0), "GetCallerIdentity", "sts", VPN_IP),
               g.ct_event(p["email"], "engineering", at(b0, 20, 4), "CreateVirtualMFADevice", "iam", VPN_IP,
                          {"virtualMFADeviceName": "backup-device"}, error="AccessDenied")]
        recon = [("ListRoles", "iam", {}), ("ListBuckets", "s3", {}),
                 ("GetBucketPolicy", "s3", {"bucketName": "acme-prod-webapp"}),
                 ("ListDistributions", "cloudfront", {}), ("DescribeInstances", "ec2", {}),
                 ("ListFunctions", "lambda", {})]
        for day_off in range(1, 13):
            for k, (name, src, prm) in enumerate(recon):
                ids.append(g.ct_event(p["email"], "engineering", at(b0 + day_off, 20, 10 + k * 4), name, src,
                                      VPN_IP, prm))
        ids.append(g.ct_event(p["email"], "engineering", at(b0 + 14, 20, 30), "GetObject", "s3", VPN_IP,
                              {"bucketName": "acme-prod-webapp", "key": "static/js/app.js"}))
        ids.append(g.ct_event(p["email"], "engineering", at(b0 + 15, 20, 45), "PutObject", "s3", VPN_IP,
                              {"bucketName": "acme-prod-webapp", "key": "static/js/app.js"}))
        labels["scenarios"].append({"name": "slow_heist", "identity": p["email"], "days": 16,
                                    "expected": "linked", "min_stages": 3, "event_ids": ids})

    # ---- 3. insider staircase (real employee, usual place and time)
    if days >= 29:
        p = by_email["meera.ops@acme.example"]
        s0 = days - 28
        per_day = [2, 4, 7, 13]
        ids = []
        for w in range(4):
            for dd in range(7):
                di = s0 + w * 7 + dd
                if di >= days or (start + timedelta(days=di)).weekday() >= 5 and di != days - 1:
                    continue
                for k in range(per_day[w]):
                    ids.append(g.ct_event(p["email"], "engineering", at(di, 11, 2 + k * 3), "GetObject", "s3",
                                          p["office_ip"], {"bucketName": "acme-finance-ledger",
                                                           "key": f"ledger/2026/part-{w}-{dd}-{k}.csv"}))
        ids.append(g.ct_event(p["email"], "engineering", at(days - 1, 12, 30), "ModifySnapshotAttribute", "ec2",
                              p["office_ip"], {"snapshotId": "snap-finance-db-0423",
                                               "attributeType": "CREATE_VOLUME_PERMISSION",
                                               "createVolumePermission": {"add": {"items": [
                                                   {"userId": EXTERNAL_ACCOUNT}]}}}))
        labels["scenarios"].append({"name": "insider_staircase", "identity": p["email"], "days": 28,
                                    "expected": "linked", "min_stages": 2, "event_ids": ids})

    # ---- 4. two risky steps 32 days apart: must NOT be linked
    if days >= 34:
        p = by_email["old.ops@acme.example"]
        ids = [g.ct_event(p["email"], "engineering", at(1, 13, 0), "AttachRolePolicy", "iam", p["office_ip"],
                          {"roleName": "ops-tools", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
               g.ct_event(p["email"], "engineering", at(33, 13, 0), "PutBucketPolicy", "s3", p["office_ip"],
                          {"bucketName": "acme-ops-shared"})]
        labels["scenarios"].append({"name": "gap_32_days", "identity": p["email"], "days": 33,
                                    "expected": "not_linked", "event_ids": ids})

    g.ct.sort(key=lambda r: r["eventTime"])
    g.okta.sort(key=lambda r: r["published"])
    labels["events"] = {"okta": len(g.okta), "cloudtrail": len(g.ct)}
    return g.okta, g.ct, labels


def write(out_dir: Path | str, days: int = 30, identities: int = 50, seed: int = 42,
          end: date | None = None) -> dict:
    out = Path(out_dir)
    (out / "okta").mkdir(parents=True, exist_ok=True)
    (out / "cloudtrail").mkdir(parents=True, exist_ok=True)
    okta, ct, labels = generate(days, identities, seed, end)
    (out / "okta" / "okta_synth.json").write_text(json.dumps(okta), encoding="utf-8")
    (out / "cloudtrail" / "cloudtrail_synth.json").write_text(json.dumps({"Records": ct}), encoding="utf-8")
    (out / "labels.json").write_text(json.dumps(labels, indent=1), encoding="utf-8")
    return {"out": str(out), "okta_events": len(okta), "cloudtrail_events": len(ct),
            "scenarios": [s["name"] for s in labels["scenarios"]], "start": labels["start"], "end": labels["end"]}


def report(engine, labels: dict) -> dict:
    """Compare findings with the synthetic ground truth."""
    findings = engine.findings(limit=1000)
    by_identity: dict[str, list[dict]] = {}
    for f in findings:
        by_identity.setdefault(f["identity"], []).append(f)
    attack_ids = {s["identity"] for s in labels.get("scenarios", [])}
    rows = []
    for s in labels.get("scenarios", []):
        fs = by_identity.get(s["identity"], [])
        best = max(fs, key=lambda f: f["risk"], default=None)
        if s["expected"] == "linked":
            ok = best is not None and len(best["stages"]) >= s.get("min_stages", 2)
        else:
            ok = not any(set(s["event_ids"]) <= set(f["evidence"]) for f in fs)
        rows.append({"scenario": s["name"], "identity": s["identity"], "expected": s["expected"], "passed": ok,
                     "risk": best["risk"] if best else 0, "stages": best["stages"] if best else [],
                     "days_spanned": best["days_spanned"] if best else 0})
    false_pos = sorted(i for i in by_identity if i not in attack_ids)
    normal_total = labels.get("identities", 0) - len(attack_ids)
    return {"scenarios": rows, "passed": sum(r["passed"] for r in rows), "total": len(rows),
            "false_positive_identities": false_pos, "false_positive_count": len(false_pos),
            "normal_identities": normal_total, "synthetic": True}
