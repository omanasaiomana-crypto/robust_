# 06 · Demo script v2.1 (6 minutes)

**Before you start:**
- Run one fresh scan, so the audit log and the replay are clean.
- Open these tabs: **Overview → Live scan → Agents → Input data → Attack path explorer (svc-report) → Analytics → Notifications → Audit**.
- Start the server without `--reload`. Keep a terminal open at the project root.

| Time | Screen | What to say | What to click |
|---|---|---|---|
| 0:00 | Overview | "Attackers don't break in, they log in. Every login here succeeded. IdentityShield joins Okta and AWS CloudTrail into one story per identity." | Stat cards, "Rules vs ML" card |
| 0:25 | Overview | "On the official labeled samples we reach event F1 **X** vs the provided baseline's **Y**." (from `docs/official/RESULTS.md`) | none |
| 0:40 | **Live scan** | "Here are 15 agents checking for malicious activity. Each line is a real step with its full JSON. The run takes about 2 seconds; we replay it slowly so you can follow." | **Start scan** at 1×, click the Privilege Escalation line to show its JSON |
| 1:30 | Live scan | "Red lines are threats. **Each threat is written to the audit log as its own entry.**" | Threat cards on the right; finish banner |
| 1:50 | **Agents** | "Five layers: data, detection, decision, learning, oversight. Each agent has its own permissions; detectors can only read." | Click the Privilege Escalation card to show its JSON |
| 2:10 | **Attack path explorer** | "This is svc-report: dormant 47 days, then key, admin policy, admin role, secret, in 11 minutes." | **▶ Play attack** (the camera follows steps 1→5) |
| 2:50 | Explorer | "What could it reach next? That's the blast radius." "Here's the evidence for each step." | **Blast radius**, **Focus attack path**, click an edge event id |
| 3:15 | **Input data** | "You can feed it your own data. Two Okta logins, Bengaluru and then Frankfurt 30 minutes later…" | Presets **Login · Bengaluru** → Add, **Login · Frankfurt +30 min** → Add, **Scan input only** |
| 3:45 | Live scan (auto) | "…and only that input is scanned: impossible travel, flagged and audited." | Watch the THREAT line appear |
| 4:05 | Alert detail | "Revocation needs a human and only goes through the supplied simulator. The admin also gets one short email." | **Approve revoke**, **Email admin** |
| 4:30 | Notifications | "One digest, not 30 emails. Usernames come from attacker-controlled logs, so we block email header injection." | Expand the digest preview |
| 4:50 | Analytics | "Which is better, rules or ML? Here's the answer measured on labeled data: **winner text**. And when are we attacked?" | Winner banner, detection heatmap, time heatmap |
| 5:30 | Audit | "Every threat, action and email is hash-chained. Our own system is tamper-evident." | **Verify again** |
| 5:45 | Terminal (optional) | "Same scan from the command line, in full color with full JSON." | `python -m app.scan --json --delay 0.05` |
| 6:00 | (close) | One-line pitch | none |

**One-line pitch:** "IdentityShield's 15 agents connect login and cloud activity into one explainable attack story. You can watch it happen step by step; every threat is audited, the admin is told in one email, and nothing is revoked without a human."

## Likely judge questions

| Question | Answer |
|---|---|
| Are the 15 agents real, or just names? | Show the Agents page and the Live scan: each card is a real step with timing and output JSON from this run. |
| Is the live scan faked? | No. It replays the real trace of the run you just triggered at a readable speed, and the banner shows the actual scan time. **Instant** speed shows it all at once. |
| Can it analyze our own logs? | Yes. Paste or upload CloudTrail/Okta JSON, or add events by form, then **Scan input only**. |
| Why didn't the dormant detector fire on my 2 events? | Dormancy needs 30+ days of history and ML needs 20+ sessions. Use **Dataset + input** for those. |
| Why not revoke real AWS sessions? | The rules require the supplied simulator, and humans approve high-impact actions. Real adapters are future scope. |
| Is ML actually useful? | Show the Analytics agreement card: what ML adds and what it costs, measured on labeled data. |
| How do you avoid alert fatigue? | One digest per run, dedupe, an hourly cap, deduplicated threat audit entries, and a friction budget for MFA. |

## Backup plan

- Screen recording of the full demo.
- `scan.html?mock=1&autostart=replay` and `graph.html?mock=1&play=1` work without the backend.
- Phase 27 vendor assets mean no Wi-Fi is needed. Keep `EMAIL_MODE=outbox` unless SMTP was tested on site.
