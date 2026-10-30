# P00: Baseline and safety net (MUST)

> **Before pasting:** open a NEW Antigravity chat and paste T1 from `00_TEMPLATES.md` first. Then paste only the text block below. Run the CHECK yourself.

```text
Read context.md. Phase P0: baseline. Do not create v3 code yet.
DO:
1. Run the existing test suite (pytest -q) and the existing smoke test if present; report results.
2. List the existing modules relevant to v3 integration and report their public functions in one line each:
   app/main.py (app creation, existing routers, static mount, lifespan or startup events),
   the simulator client/module used by the v2 response agent (exact file and function names),
   app/trace.py (emit/step/progress/finding functions), the audit module (append + verify functions),
   app/notify.py (send functions), app/inputs.py, the official dataset file paths and label format.
3. Create empty package folders with __init__.py: app/v3/, app/v3/agents/, app/v3/enrich/, app/v3/llm/,
   app/v3/ingest/, app/v3/playbooks/ (no __init__ needed), app/v3/data/, tests/v3/ (with __init__.py and conftest.py
   that adds a fixture `tmp_db` creating a temporary SQLite path and a fixture `fixed_clock`).
4. Add to .gitignore if missing: .env, data/spool/, *.sqlite-wal, *.sqlite-shm, .pytest_cache/.
5. Create .env.example by merging the existing one with the build kit's env.example.txt (it already lists every
   variable). It must contain every variable in context.md Sections 12, 15, 17 that
   comes from the environment: INGEST_KEYS, ANALYST_TOKEN, ENRICH_PROVIDERS, IPINFO_TOKEN, ABUSEIPDB_KEY,
   GREYNOISE_KEY, OTX_KEY, VT_KEY, MAXMIND_LICENSE_KEY, LLM_ENABLED, LLM_PROVIDER, GEMINI_API_KEY, GROQ_API_KEY,
   OLLAMA_URL, OPENROUTER_API_KEY, EMAIL_MODE, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ADMIN_EMAIL,
   NGROK_AUTHTOKEN (documentation only). All values empty.
6. Add to requirements.txt if missing (pinned): pyyaml, httpx, ruff, pytest (keep existing pins).
7. Write the findings of step 2 into context.md Section 20 "Known issues / decisions" as "Integration points".
FILES: app/v3/** (empty packages), tests/v3/__init__.py, tests/v3/conftest.py, .gitignore, .env.example,
requirements.txt, context.md (Section 20 only).
```

**CHECK**
```bash
pytest -q
python -c "import app.v3, app.v3.agents; print('ok')"
git status   # .env must not appear
```

---
**After the CHECK passes:** paste template T5 (in `00_TEMPLATES.md`), then commit: `git add -A && git commit -m "v3 P00: Baseline and safety net"`. Next file: `P01_contracts_and_config.md`.
