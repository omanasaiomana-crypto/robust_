# IdentityShield v3 Build Kit (Team Robust Gang)

This kit lets you continue building the IdentityShield project in **Antigravity**, phase by phase, on top of your existing v2 code, without breaking it.

## What's inside

| File | Purpose |
|---|---|
| `context.md` | **The single source of truth for Antigravity:** golden rules, architecture, the 15 agents, frozen data contracts, topics, configuration, detections, risk model, API, the 3D UI design system and the progress log. Antigravity reads it at the start of every chat. |
| `prompts/` | **One file per phase:** `00_INDEX.md` (run order and time plan), `00_TEMPLATES.md` (T1–T5), `P00_…md` to `P18_…md` (one phase each, with file list, CHECK commands and the next file to open), `99_EMERGENCY.md` |
| `FREE_APIS.md` | Every free API and service you can use (ngrok, IP intel, LLM, email): free limits, where to get the key, the `.env` variable name and the privacy rules |
| `env.example.txt` | All environment variable names with empty values; copy to `.env` |
| `docs/IdentityShield_v3_Technical_PRD.md` | The full technical PRD with 9 UML diagrams (Mermaid); prompts refer to it as "PRD §N" |

## Setup (10 minutes)

1. Commit your current project: `git add -A && git commit -m "v2 final before v3"`.
2. Copy `context.md`, the `prompts/` folder, `FREE_APIS.md`, `env.example.txt` and the `docs/` folder into the project root.
3. Copy `env.example.txt` to `.env` and fill in only `INGEST_KEYS` (one key ID and a long random secret) and `ANALYST_TOKEN` for now. Everything else is optional.
4. Open the project in Antigravity. In a new chat, paste **T1** from `prompts/00_TEMPLATES.md`, then the text block from `prompts/P00_baseline_and_safety_net.md`.

## The workflow for every phase

1. Open a **new chat**, then paste T1 (`prompts/00_TEMPLATES.md`).
2. Open that phase's file in `prompts/` and paste its text block.
3. Run the CHECK commands yourself.
4. If the CHECK fails, use T2.
5. When it passes, use T5 to update the progress log, then commit.

## Priorities if time is short

- **MUST:** P0–P7, P9–P14, P16, P18. This gives the complete live demo: signed ngrok feed → 15 agents → case with explanation → graduated response → 3D Live and Case pages.
- **SHOULD:** P8 (ML + campaign), P15 (3D graph, globe, analytics, performance pages), P17 calibration.
- Always run **P17 evaluation + benchmark** before judging, so every number you present is measured.

## The rules that keep the backend strong

- v3 lives in `app/v3/` and `static/v3/`; v2 keeps working.
- Each agent is a pure `process(message, state)` unit. The same code runs in drain mode (tests, dataset metrics) and live mode (demo).
- Frozen contracts, typed models, bounded queues, capability manifests, dead-letter handling, audit for every decision, tests and `ruff` in every phase.
- Only the Response agent can reach the simulator, and revoke always needs analyst approval.

## Demo-day summary

Run the core app on laptop 1, then start ngrok on port 8001 (ingest only). Open the generator on laptop 2, paste the URL, key and secret, and click E1. The Live page shows the 3D agent constellation lighting up. The case appears with risk ≥ 90, the attack chain, a what-if score and the predicted next step. Restrict is applied automatically. You approve the revoke and the audit entry appears. Then run the evasion pack and the tamper tests, and finish on the measured metrics. Full script: PRD §30.
