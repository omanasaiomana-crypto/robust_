"""Realistic sample CloudTrail and Okta log generator with all 5 attack scenarios."""
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

from app.config import SAMPLE_DIR

log = logging.getLogger(__name__)

INDIAN_LOCATIONS = [
    {"city": "Bengaluru", "country": "India", "lat": 12.9716, "lon": 77.5946, "asn": "AS9498", "ip_prefix": "103.21.244"},
    {"city": "Mysuru", "country": "India", "lat": 12.2958, "lon": 76.6394, "asn": "AS9498", "ip_prefix": "103.21.245"},
    {"city": "Chennai", "country": "India", "lat": 13.0827, "lon": 80.2707, "asn": "AS45609", "ip_prefix": "103.50.162"},
    {"city": "Hyderabad", "country": "India", "lat": 17.3850, "lon": 78.4867, "asn": "AS55836", "ip_prefix": "103.88.220"},
]

NORMAL_USERS = [
    ("anita.rao", 5, ["Admins", "Engineering"]),
    ("dev.kumar", 3, ["Engineering", "DevOps"]),
    ("meera.n", 3, ["Security", "Operations"]),
    ("rahul.sharma", 2, ["Engineering"]),
    ("priya.patel", 2, ["Engineering", "Frontend"]),
    ("arjun.singh", 2, ["Engineering", "Backend"]),
    ("neha.gupta", 2, ["DataPlatform"]),
    ("vikram.verma", 2, ["Infrastructure"]),
    ("pooja.reddy", 2, ["Product"]),
    ("kavita.nair", 2, ["Engineering", "QA"]),
    ("rohit.joshi", 2, ["Engineering"]),
    ("sanjay.iyer", 2, ["DatabaseAdmin"]),
    ("deepa.menon", 2, ["Support"]),
    ("alok.mishra", 2, ["Engineering"]),
    ("sunita.deshmukh", 2, ["Finance"]),
    ("amit.bose", 2, ["Operations"]),
    ("swati.kulkarni", 2, ["Engineering"]),
    ("manoj.pillai", 2, ["SecurityAuditor"]),
    ("divya.choudhury", 2, ["Engineering"]),
]

SVC_REPORT = ("svc-report", 1, ["ServiceAccounts", "Reporting"])

ROUTINE_ACTIONS = [
    ("GetObject", "s3.amazonaws.com", "arn:aws:s3:::corp-data-lake-reports/daily.parquet"),
    ("ListBuckets", "s3.amazonaws.com", "arn:aws:s3:::*"),
    ("DescribeInstances", "ec2.amazonaws.com", "arn:aws:ec2:ap-south-1:123456789012:instance/*"),
    ("DescribeSecurityGroups", "ec2.amazonaws.com", "arn:aws:ec2:ap-south-1:123456789012:security-group/*"),
    ("GetCallerIdentity", "sts.amazonaws.com", "arn:aws:sts::123456789012:user"),
]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate(out_dir: Path, days: int = 60) -> dict:
    """Generate realistic CloudTrail and Okta logs with 5 attack scenarios."""
    random.seed(42)
    out_dir.mkdir(parents=True, exist_ok=True)

    end_date = datetime(2026, 10, 28, 0, 0, 0, tzinfo=timezone.utc)
    start_date = end_date - timedelta(days=days)

    cloudtrail_records = []
    okta_records = []
    counts = {
        "benign": 0,
        "impossible_travel": 0,
        "dormant_reactivation": 0,
        "privilege_escalation": 0,
        "unusual_api": 0,
        "token_abuse": 0,
    }

    metadata = []
    all_identities = NORMAL_USERS + [SVC_REPORT]
    for uid, priv, groups in all_identities:
        metadata.append({
            "identity_id": uid,
            "email": f"{uid}@corp.example",
            "privilege_level": priv,
            "groups": groups,
        })

    # Sequence counter for unique IDs
    ct_counter = 1
    okta_counter = 1
    session_counter = 1000

    def make_okta_event(ts: datetime, uid: str, event_type: str, loc: dict, session_id: str,
                        outcome: str = "SUCCESS", label: str = "benign", ip_override: str | None = None,
                        ua_override: str | None = None) -> dict:
        nonlocal okta_counter
        ip = ip_override or f"{loc['ip_prefix']}.{random.randint(2, 250)}"
        ua = ua_override or f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/{random.randint(120, 126)}.0.0.0 Safari/537.36"
        evt = {
            "uuid": f"okta-{okta_counter:06d}",
            "published": _iso(ts),
            "eventType": event_type,
            "actor": {
                "id": f"00u{uid.replace('.', '')[:8]}",
                "alternateId": f"{uid}@corp.example",
            },
            "outcome": {"result": outcome},
            "client": {
                "ipAddress": ip,
                "userAgent": {"rawUserAgent": ua},
                "geographicalContext": {
                    "country": loc["country"],
                    "city": loc["city"],
                    "geolocation": {"lat": loc["lat"], "lon": loc["lon"]},
                },
            },
            "authenticationContext": {"externalSessionId": session_id},
            "securityContext": {"asNumber": loc["asn"]},
            "label": label,
        }
        okta_counter += 1
        return evt

    def make_ct_event(ts: datetime, uid: str, action: str, service: str, resource: str,
                      ip: str, region: str = "ap-south-1", label: str = "benign",
                      access_key: str | None = None, req_params: dict | None = None,
                      error_code: str | None = None, ua: str | None = None) -> dict:
        nonlocal ct_counter
        ak = access_key or f"AKIA{uid[:4].upper()}{random.randint(1000, 9999)}KEY"
        evt = {
            "eventID": f"ct-{ct_counter:07d}",
            "eventTime": _iso(ts),
            "eventName": action,
            "eventSource": service,
            "awsRegion": region,
            "sourceIPAddress": ip,
            "userAgent": ua or "aws-sdk-python/1.34.0 Boto3/1.34.0 Python/3.11.8",
            "userIdentity": {
                "type": "IAMUser",
                "userName": uid,
                "arn": f"arn:aws:iam::123456789012:user/{uid}",
                "accessKeyId": ak,
            },
            "requestParameters": req_params or {},
            "resources": [{"ARN": resource}] if resource else [],
            "label": label,
        }
        if error_code:
            evt["errorCode"] = error_code
        ct_counter += 1
        return evt

    # 1. Normal routine generation across the 60-day window
    for day_idx in range(days - 2):
        curr_day = start_date + timedelta(days=day_idx)
        # Skip weekends
        if curr_day.weekday() >= 5:
            continue

        # Normal users
        for uid, _, _ in NORMAL_USERS:
            # 80% chance of login on any given workday
            if random.random() > 0.85:
                continue

            session_id = f"okta:sess-{session_counter}"
            session_counter += 1
            loc = random.choice(INDIAN_LOCATIONS)
            ip = f"{loc['ip_prefix']}.{random.randint(10, 240)}"

            # Login between 09:00 and 10:30 IST (03:30 to 05:00 UTC)
            login_hour = 3
            login_min = random.randint(30, 59)
            login_ts = curr_day.replace(hour=login_hour, minute=login_min, second=random.randint(0, 59))

            okta_evt = make_okta_event(login_ts, uid, "user.session.start", loc, session_id, ip_override=ip)
            okta_records.append(okta_evt)
            counts["benign"] += 1

            # 2 to 5 routine API actions during the workday
            num_actions = random.randint(2, 5)
            ak = f"AKIA{uid[:4].upper()}NORM{random.randint(100, 999)}"
            for a_idx in range(num_actions):
                act_time = login_ts + timedelta(minutes=random.randint(15, 480))
                act_name, act_svc, act_res = random.choice(ROUTINE_ACTIONS)
                ct_evt = make_ct_event(act_time, uid, act_name, act_svc, act_res, ip=ip, access_key=ak)
                cloudtrail_records.append(ct_evt)
                counts["benign"] += 1

        # svc-report is active ONLY during the first 6 days (days 0-5), then stays silent for 52 days!
        if day_idx <= 5:
            session_id = f"okta:svc-sess-{session_counter}"
            session_counter += 1
            loc = INDIAN_LOCATIONS[0]
            ip = "103.21.244.5"
            login_ts = curr_day.replace(hour=4, minute=0, second=0)
            okta_records.append(make_okta_event(login_ts, "svc-report", "user.session.start", loc, session_id, ip_override=ip))
            counts["benign"] += 1

            for _ in range(3):
                act_time = login_ts + timedelta(minutes=random.randint(5, 60))
                cloudtrail_records.append(make_ct_event(
                    act_time, "svc-report", "GetObject", "s3.amazonaws.com",
                    "arn:aws:s3:::corp-data-lake-reports/batch.json", ip=ip, access_key="AKIA_SVC_REP_KEY"
                ))
                counts["benign"] += 1

    # Attack window: last 2 days (days 58 and 59)
    # Day 58: 2026-10-26 (UTC)
    day_58 = start_date + timedelta(days=days - 2)
    # Day 59: 2026-10-27 (UTC)
    day_59 = start_date + timedelta(days=days - 1)

    # --- Scenario S1: impossible_travel (anita.rao) on Day 58 ---
    # Login 1: Bengaluru at 04:00:00Z
    s1_sess_1 = f"okta:sess-anita-{session_counter}"
    session_counter += 1
    t_s1_1 = day_58.replace(hour=4, minute=0, second=0)
    loc_blr = INDIAN_LOCATIONS[0]
    okta_records.append(make_okta_event(t_s1_1, "anita.rao", "user.session.start", loc_blr, s1_sess_1,
                                        label="impossible_travel", ip_override="103.21.244.11"))
    cloudtrail_records.append(make_ct_event(t_s1_1 + timedelta(minutes=5), "anita.rao", "DescribeInstances",
                                            "ec2.amazonaws.com", "arn:aws:ec2:ap-south-1:123456789012:instance/*",
                                            ip="103.21.244.11", label="impossible_travel"))
    counts["impossible_travel"] += 2

    # Login 2: Frankfurt 30 minutes later at 04:30:00Z (7,400+ km away)
    s1_sess_2 = f"okta:sess-anita-{session_counter}"
    session_counter += 1
    t_s1_2 = day_58.replace(hour=4, minute=30, second=0)
    loc_fra = {"city": "Frankfurt", "country": "Germany", "lat": 50.1109, "lon": 8.6821, "asn": "AS24940", "ip_prefix": "194.12.45"}
    okta_records.append(make_okta_event(t_s1_2, "anita.rao", "user.session.start", loc_fra, s1_sess_2,
                                        label="impossible_travel", ip_override="194.12.45.67"))
    cloudtrail_records.append(make_ct_event(t_s1_2 + timedelta(minutes=2), "anita.rao", "ListBuckets",
                                            "s3.amazonaws.com", "arn:aws:s3:::*",
                                            ip="194.12.45.67", label="impossible_travel"))
    counts["impossible_travel"] += 2

    # --- Scenario S2: dormant_reactivation (svc-report) on Day 58 ---
    # svc-report was dormant for > 47 days (since day 5, ~52 days ago)
    t_s2 = day_58.replace(hour=7, minute=15, second=0)
    s2_sess = f"okta:sess-svc-{session_counter}"
    session_counter += 1
    okta_records.append(make_okta_event(t_s2, "svc-report", "user.session.start", loc_blr, s2_sess,
                                        label="dormant_reactivation", ip_override="103.21.244.5"))
    cloudtrail_records.append(make_ct_event(t_s2 + timedelta(minutes=1), "svc-report", "DescribeInstances",
                                            "ec2.amazonaws.com", "arn:aws:ec2:ap-south-1:123456789012:instance/*",
                                            ip="103.21.244.5", label="dormant_reactivation"))
    counts["dormant_reactivation"] += 2

    # --- Scenario S3: privilege_escalation chain (svc-report) on Day 59 ---
    # Sequence within 15 minutes: CreateAccessKey -> AttachUserPolicy -> AssumeRole -> GetSecretValue
    t_s3_base = day_59.replace(hour=8, minute=0, second=0)
    s3_sess = f"okta:sess-svc-esc-{session_counter}"
    session_counter += 1
    okta_records.append(make_okta_event(t_s3_base, "svc-report", "user.session.start", loc_blr, s3_sess,
                                        label="privilege_escalation", ip_override="103.21.244.99"))
    counts["privilege_escalation"] += 1

    s3_steps = [
        (1, "CreateAccessKey", "iam.amazonaws.com", "arn:aws:iam::123456789012:user/svc-report",
         {"userName": "svc-report"}),
        (4, "AttachUserPolicy", "iam.amazonaws.com", "arn:aws:iam::123456789012:user/svc-report",
         {"userName": "svc-report", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        (8, "AssumeRole", "sts.amazonaws.com", "arn:aws:iam::123456789012:role/AdminRole",
         {"roleArn": "arn:aws:iam::123456789012:role/AdminRole"}),
        (12, "GetSecretValue", "secretsmanager.amazonaws.com", "arn:aws:secretsmanager:ap-south-1:123456789012:secret:prod/db/credentials-XYZ",
         {"secretId": "prod/db/credentials"}),
    ]
    for min_offset, act_name, svc, res, rparams in s3_steps:
        cloudtrail_records.append(make_ct_event(
            t_s3_base + timedelta(minutes=min_offset), "svc-report", act_name, svc, res,
            ip="103.21.244.99", label="privilege_escalation", req_params=rparams
        ))
        counts["privilege_escalation"] += 1

    # --- Scenario S4: unusual_api (dev.kumar) on Day 59 ---
    # StopLogging in a never-used region (eu-west-3)
    t_s4 = day_59.replace(hour=10, minute=30, second=0)
    s4_sess = f"okta:sess-dev-{session_counter}"
    session_counter += 1
    okta_records.append(make_okta_event(t_s4, "dev.kumar", "user.session.start", loc_blr, s4_sess,
                                        label="unusual_api", ip_override="103.21.244.15"))
    cloudtrail_records.append(make_ct_event(
        t_s4 + timedelta(minutes=5), "dev.kumar", "StopLogging", "cloudtrail.amazonaws.com",
        "arn:aws:cloudtrail:eu-west-3:123456789012:trail/corp-audit",
        ip="103.21.244.15", region="eu-west-3", label="unusual_api",
        req_params={"name": "arn:aws:cloudtrail:eu-west-3:123456789012:trail/corp-audit"}
    ))
    counts["unusual_api"] += 2

    # --- Scenario S5: token_abuse (meera.n) on Day 59 ---
    # Same token from India and Brazil within 3 minutes; followed by use after session end
    t_s5 = day_59.replace(hour=11, minute=0, second=0)
    s5_sess = f"okta:sess-meera-{session_counter}"
    session_counter += 1
    stolen_token = "ASIA_MEERA_STOLEN_99"

    # Initial login & use from India
    okta_records.append(make_okta_event(t_s5, "meera.n", "user.session.start", loc_blr, s5_sess,
                                        label="token_abuse", ip_override="103.21.244.20"))
    cloudtrail_records.append(make_ct_event(
        t_s5 + timedelta(seconds=30), "meera.n", "GetObject", "s3.amazonaws.com",
        "arn:aws:s3:::corp-data-lake-reports/finance.csv",
        ip="103.21.244.20", region="ap-south-1", label="token_abuse", access_key=stolen_token
    ))

    # Same access key used from Brazil 2 minutes later
    cloudtrail_records.append(make_ct_event(
        t_s5 + timedelta(minutes=2, seconds=15), "meera.n", "ListBuckets", "s3.amazonaws.com",
        "arn:aws:s3:::*",
        ip="177.18.90.12", region="sa-east-1", label="token_abuse", access_key=stolen_token,
        ua="aws-cli/2.15.15 Python/3.11.6 Linux/5.15.0"
    ))

    # Session ends at 11:10
    okta_records.append(make_okta_event(t_s5 + timedelta(minutes=10), "meera.n", "user.session.end", loc_blr, s5_sess,
                                        label="token_abuse", ip_override="103.21.244.20"))

    # Post session end use of token at 11:14
    cloudtrail_records.append(make_ct_event(
        t_s5 + timedelta(minutes=14), "meera.n", "DescribeInstances", "ec2.amazonaws.com",
        "arn:aws:ec2:sa-east-1:123456789012:instance/*",
        ip="177.18.90.12", region="sa-east-1", label="token_abuse", access_key=stolen_token
    ))
    counts["token_abuse"] += 5

    # Sort all records by timestamp
    cloudtrail_records.sort(key=lambda r: r["eventTime"])
    okta_records.sort(key=lambda r: r["published"])

    # Write files
    ct_file = out_dir / "cloudtrail.json"
    okta_file = out_dir / "okta.json"
    meta_file = out_dir / "metadata.json"

    with open(ct_file, "w", encoding="utf-8") as f:
        json.dump({"Records": cloudtrail_records}, f, indent=2)

    with open(okta_file, "w", encoding="utf-8") as f:
        json.dump(okta_records, f, indent=2)

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    counts["total_cloudtrail"] = len(cloudtrail_records)
    counts["total_okta"] = len(okta_records)
    counts["total_identities"] = len(metadata)

    log.info("Sample data generated in %s: %s", out_dir, counts)
    return counts


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    summary = generate(SAMPLE_DIR)
    print("Generation complete:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
