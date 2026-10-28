# P7 · Fix list (Persons A + D, 30 min)

Send **one FIX prompt per problem** (template below), the most visible problem first. Common cases:

| Symptom | Likely cause | What to do |
|---|---|---|
| Explorer area empty | Wrong vis-network script path in `explorer.html` | Set it to `/vendor/vis-network.min.js` if that file exists, otherwise `https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js` |
| Agents page all Idle | No scan run yet since server start | Run one Live scan |
| Live scan shows only orchestrator lines | P2 not done or wrappers missing | Redo P2 |
| Explorer: "Path steps —" | Evidence edges were cut by the 150-node cap | FIX: "in identity_subgraph keep edges whose event_id is in suspicious_ids first when trimming" |
| Input scan: "No input data" | Nothing added, or loader filter | Add presets first; otherwise redo P3 step 3 |

`git commit -am "P7 fixes"` after each fix that passes.


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
