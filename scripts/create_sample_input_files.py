"""Generate rich, realistic sample data files for manual upload and automated loading.

Outputs:
1. static/samples/sample_attack_scenario.json (All 5 multi-stage attack scenarios)
2. static/samples/sample_cloudtrail.json (CloudTrail audit logs with IAM & S3 actions)
3. static/samples/sample_okta.json (Okta session and authentication logs)
4. Desktop copy in IdentityShield_Sample_Data folder for easy user drag-and-drop
"""
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_SAMPLES = BASE_DIR / "static" / "samples"
DATA_SAMPLES = BASE_DIR / "data" / "samples"
STATIC_SAMPLES.mkdir(parents=True, exist_ok=True)
DATA_SAMPLES.mkdir(parents=True, exist_ok=True)

# Load existing sample dataset to extract pristine records
sample_ct_path = BASE_DIR / "data" / "sample" / "cloudtrail.json"
sample_ok_path = BASE_DIR / "data" / "sample" / "okta.json"

with open(sample_ct_path, encoding="utf-8") as f:
    ct_full = json.load(f)["Records"]

with open(sample_ok_path, encoding="utf-8") as f:
    ok_full = json.load(f)

# 1. Extract attack records (11 CT + 7 Okta)
ct_attacks = [r for r in ct_full if r.get("label") and r.get("label") != "benign"]
ok_attacks = [r for r in ok_full if r.get("label") and r.get("label") != "benign"]

# Combined attack scenario: list of all 18 attack events
attack_scenario = ct_attacks + ok_attacks

# 2. Extract curated CloudTrail sample: 50 records (40 benign + 10 attack)
benign_ct = [r for r in ct_full if not r.get("label") or r.get("label") == "benign"]
sample_cloudtrail = {"Records": benign_ct[:40] + ct_attacks}

# 3. Extract curated Okta sample: 30 records (23 benign + 7 attack)
benign_ok = [r for r in ok_full if not r.get("label") or r.get("label") == "benign"]
sample_okta = benign_ok[:23] + ok_attacks

# Write to static/samples/ and data/samples/
files = {
    "sample_attack_scenario.json": attack_scenario,
    "sample_cloudtrail.json": sample_cloudtrail,
    "sample_okta.json": sample_okta,
}

for name, data in files.items():
    for folder in (STATIC_SAMPLES, DATA_SAMPLES):
        p = folder / name
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Wrote {p} ({p.stat().st_size:,} bytes)")

# Also write to user's Desktop for direct drag-and-drop
desktop_paths = [
    Path("C:/Users/Omana/OneDrive/Desktop/IdentityShield_Sample_Data"),
    Path("C:/Users/Omana/Desktop/IdentityShield_Sample_Data"),
]

readme_content = """# IdentityShield Sample Datasets for Upload

This folder contains realistic sample log files ready to upload or drag-and-drop into the IdentityShield "Input Data" page (http://127.0.0.1:8000/input.html):

1. `sample_attack_scenario.json` (18 events, 5 attack chains)
   - Contains all 5 multi-agent detection attack scenarios:
     * Anita Rao (Impossible Travel: Bengaluru -> Frankfurt in 30 mins)
     * svc-report (Dormant Reactivation & 4-step IAM Privilege Escalation)
     * Dev Kumar (StopLogging Defense Evasion API Anomaly)
     * Meera N (Token Abuse & Concurrent Session Hijack)
   - Auto-detects both CloudTrail and Okta logs upon upload.

2. `sample_cloudtrail.json` (51 AWS CloudTrail records)
   - Formatted in standard AWS {"Records": [...]} schema.
   - Contains routine STS, S3, and EC2 calls alongside privilege escalation chains.

3. `sample_okta.json` (30 Okta System Log records)
   - Formatted in standard Okta JSON array schema.
   - Contains legitimate Indian workforce logins alongside suspicious foreign authentication.

### How to use:
- Open http://127.0.0.1:8000/input.html
- Drag any of these .json files into the drop box, or click "⚡ Quick-Load Sample Attack Scenario"
- Click "Scan input only" to watch all 15 agents analyze your uploaded logs!
"""

for d_path in desktop_paths:
    try:
        d_path.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            dp = d_path / name
            with open(dp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        with open(d_path / "README.txt", "w", encoding="utf-8") as f:
            f.write(readme_content)
        print(f"Populated Desktop folder: {d_path}")
    except Exception as e:
        print(f"Could not write to {d_path}: {e}")

print("Sample generation complete!")
