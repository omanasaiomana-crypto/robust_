# Prompt templates (use any time)


### T1: Session start (send once whenever you open a new Antigravity chat)

```text
Read context.md fully. It is the single source of truth for this project.
Summarize in 5 bullet points: what we are building, the golden rules, the tech stack,
the current progress from Section 12, and the next phase to do.
Do not write any code yet.
```

### T2: Fix an error (use whenever a CHECK fails)

```text
Read context.md Section 2 (golden rules).
The CHECK for Phase <N> failed with this exact output:
<paste full traceback or console error>
Fix ONLY the cause of this error, ONLY in these files: <file list>.
Do not refactor, rename, add dependencies, or touch other files.
Explain the root cause in one sentence, then show the change.
```

### T3: Resume after interruption

```text
Read context.md. Look at Section 12 (progress log) and the files that exist in the project.
Tell me which phase is in progress, which files of that phase exist, and what is missing.
Do not write code until I confirm.
```

### T4: Scope guard (send if the agent goes off-track)

```text
Stop. Revert any change to files not named in the current prompt.
Follow context.md Section 2 rule 10: only modify the files named in the prompt.
```