# P5 · Buttons and links (Person D, 15 min)

```text
Modify ONLY static/js/overview.js, static/js/alert.js and static/js/identities.js.
1. overview.js: add a primary button "Run live scan" in the page header linking to scan.html?autostart=1
   (when ?mock=1 is in the URL: scan.html?mock=1&autostart=replay).
2. alert.js: (a) change the "Open identity graph" link to explorer.html?identity=<identity_id>&play=1 (keep ?mock=1);
   (b) add a secondary button "Email admin" that calls the existing api() helper with path `/alerts/<id>/notify`
   and method POST (the helper adds /api), then a toast: status "outbox" -> "Email saved to outbox (demo mode)",
   "sent" -> "Email sent", "mocked" -> "Mock mode: nothing sent", otherwise the detail text as an error toast.
3. identities.js: rows link to explorer.html?identity=<id> instead of graph.html.
Change nothing else.
```

**CHECK:** the Overview button opens the Live scan; on an alert, **Email admin** shows a toast and the graph link opens the explorer with playback; identity rows open the explorer.
`git commit -am "P5 links"`


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
