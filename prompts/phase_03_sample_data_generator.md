# PHASE 3: Sample data generator (≈15 min) · Person B

```text
Read context.md fully. Then read docs/TECH_PRD.md Sections 9.3, 9.4 and 20.4.

GOAL: Generate realistic CloudTrail and Okta sample logs with all 5 attack scenarios, so the
whole system works without official data.

DO: write app/sample_data.py with:
  def generate(out_dir: Path, days: int = 60) -> dict  (returns counts per scenario)

Requirements:
- random.seed(42); timestamps are ISO strings ending in "Z"; base date = 60 days before 2026-10-28.
- Write out_dir/cloudtrail.json as {"Records": [...]} using real CloudTrail field names:
  eventID, eventTime, eventName, eventSource, awsRegion, sourceIPAddress, userAgent,
  userIdentity {type, userName, arn, accessKeyId}, requestParameters, resources, errorCode (rare).
- Write out_dir/okta.json as a JSON array using real Okta field names:
  uuid, published, eventType, actor {id, alternateId}, outcome {result},
  client {ipAddress, userAgent {rawUserAgent}, geographicalContext {country, city,
  geolocation {lat, lon}}}, authenticationContext {externalSessionId}, securityContext {asNumber}.
- Write out_dir/metadata.json: list of identities with identity_id, email, privilege_level, groups.
- Every record has a top-level "label": "benign" or the scenario name.
- Normal behavior: 20 users (Indian first names, e.g. anita.rao, dev.kumar, meera.n, plus
  svc-report service account), weekday logins 09:00–18:00 IST from Bengaluru/Mysuru/Chennai/Hyderabad
  with correct lat/lon, routine actions (s3:GetObject, ec2:DescribeInstances, ListBuckets).
- Okta email local part must equal the AWS userName (e.g. dev.kumar@corp.example / dev.kumar).
- Scenarios exactly as in TECH_PRD 20.4:
  S1 impossible_travel (anita.rao: Bengaluru then Frankfurt 30 min later),
  S2 dormant_reactivation (svc-report silent 47 days, then active),
  S3 privilege_escalation (svc-report: CreateAccessKey → AttachUserPolicy AdministratorAccess
     → AssumeRole AdminRole → GetSecretValue within 15 minutes),
  S4 unusual_api (dev.kumar: StopLogging in a never-used region),
  S5 token_abuse (meera.n: same accessKeyId from India and Brazil within 3 minutes, and use after
     an Okta user.session.end).
- Place all attack scenarios in the last 2 days of the window.
- Add if __name__ == "__main__": generate(SAMPLE_DIR) and log counts.

FILES: app/sample_data.py only.

CHECK:
python -m app.sample_data
python -c "import json; d=json.load(open('data/sample/cloudtrail.json',encoding='utf-8')); print(len(d['Records']))"
Expected: a few thousand records and the 3 files in data/sample/.
Then update context.md Section 12: Phase 3 = ☑.
```

---

**After the CHECK passes:** `git add . && git commit -m "phase 3 ok"`, then open the next file.
**If the CHECK fails:** use template T2 in `prompts/00_templates.md` with the exact error.
