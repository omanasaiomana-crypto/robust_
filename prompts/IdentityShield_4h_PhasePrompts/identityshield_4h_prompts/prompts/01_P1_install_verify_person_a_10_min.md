# P1 · Install + verify (Person A, 10 min)

```text
Run these commands in the project root, in order, and report each output. Do NOT edit any file in this phase.
1. python install_v21.py
2. python -m pytest -q
3. python smoke_test.py
If step 1 prints [TODO] lines, that is expected for: "traced steps", "input_mode", "sidebar links".
Any OTHER [TODO] line, a failing test or a smoke-test failure: show me the full output and stop.
```

**CHECK:** the installer shows `[OK]` for files, config, pages, `main.py`, compile and the `app.api.v21` import; pytest passes; the smoke test passes.
`git add . && git commit -m "P1 installed"`


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
