# START HERE · IdentityShield v2.1 build kit

This kit continues your finished v1 project (phases 0–19). It reviews the Antigravity audit, fixes its gaps, and adds:

| Feature | Phases |
|---|---|
| Official data, baseline comparison, predictions export, real latency | 21 |
| Detection analytics: rules vs ML vs hybrid, detection heatmap, attack-time heatmap | 22–23 |
| Admin email alerts (digest, dedupe, rate limit, outbox for offline demos) | 24–25 |
| Background re-runs, offline assets, optional analyst token, supplied simulator | 26–29 |
| **All 15 agents visible on a live Agents dashboard** | 31–32 |
| **Live scan: full-color console + full JSON of every step, current state and step** (also in the terminal) | 31, 33 |
| **One audit-log entry per detected threat** | 31 |
| **Input-only data entry: paste, upload or form, then scan only that input** | 34–35 |
| **Attack Path Explorer: animated attack path, playback, focus, blast radius** | 36 |

Every file in this kit is Markdown. Tested code is inside `reference/` as code blocks; the prompts tell Antigravity to copy it exactly.

## What's inside

| File | Purpose |
|---|---|
| `01_AUDIT_REVIEW.md` | Review of the audit: what's right, inconsistencies, missed gaps, what to follow or skip |
| `02_DEVELOPMENT_PLAN.md` | Phases 20–36, run order, priorities, owners, definition of done |
| `03_FEATURE_ANALYTICS_SPEC.md` | Heatmaps + rules-vs-ML spec |
| `04_FEATURE_EMAIL_ALERTS_SPEC.md` | Email alerts spec (security, `.env`, Gmail) |
| `05_CONTEXT_V2_ADDENDUM.md` | Sections 15–20 for `context.md` (Phase 20 appends them) |
| `05b_CONTEXT_V21_ADDENDUM.md` | Sections 21–24 for `context.md` (Phase 31 appends them) |
| `06_DEMO_SCRIPT_V2.md` | 6-minute demo, judge Q&A, backup plan |
| `07_FUTURE_SCOPE.md` | Production roadmap for slides |
| `08_FEATURE_AGENTS_SCAN_INPUT_GRAPH_SPEC.md` | v2.1 spec: 15 agents, live scan, threat audit, data input, attack path explorer |
| `prompts/` | One prompt file per phase + templates |
| `BUILD_PROMPTS_V2.md` | All prompts in one file |
| `reference/` | Pre-tested code (Python backend, browser JS) + mock JSON + the checker tool |

## What was tested before packaging

- **Python:** 23 of 23 reference tests pass. They cover analytics, email (dedupe, rate limit, header injection, SMTP fallback), the background runner, the 15-agent trace, threat audit entries (including chain integrity), the terminal scan and data input (formats, limits, path safety, form validation).
- **Browser JS:** the JSON highlighter and the attack-path logic pass unit tests in Node (including XSS strings).
- **Live scan page:** runs in headless Chromium in mock mode, live mode with a simulated API, and autostart mode. All 32 events render, 4 threats are found, and there are 0 browser errors.
- **Attack Path Explorer:** the logic runs in headless Chromium against a vis-network stand-in, with 0 browser errors. **The real visual rendering must be checked in your browser** (Phase 36 CHECK).

## How to run it

1. Copy the `kit_v2/` folder into your project root (next to `context.md`), then `git checkout -b v2`.
2. In a new Antigravity chat, send **T1** from `prompts/00_templates_v2.md`.
3. Run phases in this order, one prompt (or one part) per message:

   **20 → 21 → 22 → 23 → 24 → 25 → 26 → 27 → 31 → 32 → 33 → 34 → 35 → 36 → (28, 29 optional) → 30 last**

4. After each phase: run its CHECK, then `git commit`.
5. If a CHECK fails, send **T2**. If the agent drifts, send **T4**. To prove tested code was not changed, run **T5**.

**Already did some v2 phases?** That's fine. Phase 31 Part A checks the reference files and replaces outdated ones, including the older v2 runner.

## Priorities if time is short

| Must | Should | Could |
|---|---|---|
| 20, 21, 24, 26, 31, 33, 36, 30 | 22, 23, 25, 32, 34, 35, 27 | 28, 29 (29 becomes Must once the organizers publish the simulator interface) |

## Parallel split (4 people)

| Person | Phases |
|---|---|
| A | 20 → 24 → 26 → 31 → 36 (Part A) → 28/29 |
| B | 21 → 34 |
| C | 22 → help with 21 (tuning) → help with 31 Part B (pipeline wrappers) |
| D | 23 → 25 → 27 → 32 → 33 → 35 → 36 (Part B), all in `?mock=1` first |

All four do Phase 30 together.

## Rules that keep the backend error-free

1. Never let the agent regenerate `kit_v2/reference/` code. Copy it exactly and verify with `tools/check_ref.py`.
2. No new dependencies, no real AWS/Okta calls, and `app/models.py` stays frozen.
3. One phase (or part) per message. Run the CHECK, commit, then move on.
