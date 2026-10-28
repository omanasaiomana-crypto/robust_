# P10 · Freeze + demo data (all, 15 min)

```bash
python -c "from app import inputs; print(inputs.clear_inputs())"
git add . && git commit -m "demo freeze" && git tag demo-final
python -m uvicorn app.main:app --port 8000
```

1. Open the **Live scan** page and run **Start scan** once, so the audit log and the replay are fresh.
2. Pre-open tabs: Live scan, Agents, Attack paths (svc-report), Input data, the svc-report alert, Analytics, Audit.
3. Record a 3-minute backup video.
4. **No code changes after this point.**

**Demo order (6 min):** Live scan → Agents → Attack paths (Play attack) → Input data (2 presets → Scan input only) → Alert (Approve revoke, Email admin) → Analytics → Audit (Verify).


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
