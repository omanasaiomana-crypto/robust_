# Templates (use in every phase)

## T1: Session start (paste at the start of EVERY new chat)

```text
Read context.md completely. Then read docs/IdentityShield_v3_Technical_PRD.md sections relevant to the phase I will give you.
Reply with exactly:
1) Six bullets: what IdentityShield v3 is, the 12 golden rules in one line each (compressed), the agent model (process(message,state) + drain/live modes), the files you must never rewrite, the current progress from context.md Section 20, and the next phase.
2) "Ready for phase <N>".
Do not write any code yet.
```

## T2: Fix a failed CHECK

```text
The CHECK for phase <N> failed. Exact output:
<paste the full output or traceback>
Read context.md Sections 2, 7 and the files named in the traceback only.
Find the root cause. Fix it with the smallest possible change, only in files listed for phase <N>.
Do not change tests to make them pass unless the test contradicts context.md; if so, explain first.
Then re-run the same CHECK commands and show me the output.
```

## T3: Scope guard

```text
Stop. You edited files outside the phase <N> file list: <list>.
Revert those changes (git checkout -- <files>) unless they are required; if required, explain why in 3 lines and wait for my OK.
```

## T4: Context refresh mid-phase

```text
Re-read context.md Sections 2, 5, 7, 8, 9 and the phase <N> prompt above. Summarize in 5 bullets what is done and what remains for phase <N>, then continue.
```

## T5: End of phase

```text
Phase <N> CHECK passed. Update context.md Section 20: set phase <N> to "done", today's date, and 1–3 notes (decisions, bugs found, anything the next phase must know). Change nothing else.
```

