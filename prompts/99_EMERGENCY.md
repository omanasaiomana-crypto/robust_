# Emergency prompts

**The live demo breaks 30 minutes before judging**
```text
Do not refactor. Read context.md Section 2 and 20. The following fails: <exact symptom + error>.
Give me the smallest fix or a safe fallback (e.g. disable LLM, disable providers, switch generator to localhost,
use dataset run instead of live) and the exact commands to verify. Touch at most 2 files.
```

**Antigravity lost context / repeats work**
```text
Read context.md Section 20 and git log --oneline -15. Tell me the last completed phase and what is half-done in the
working tree (git status, git diff --stat). Do not write code until I confirm the next step.
```
