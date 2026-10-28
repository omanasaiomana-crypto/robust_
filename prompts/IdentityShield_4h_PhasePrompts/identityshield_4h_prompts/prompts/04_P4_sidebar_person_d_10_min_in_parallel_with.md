# P4 · Sidebar (Person D, 10 min, in parallel with P2)

```text
Modify ONLY static/js/layout.js.
Add sidebar items in the same style as the existing ones (inline SVG icon + label, keep ?mock=1 on links like the
existing items). Final order:
Overview, Live scan (scan.html, id "scan"), Agents (agents.html, id "agents"), Input data (input.html, id "input"),
Alerts, Identities, Attack paths (explorer.html, id "explorer"), Analytics (analytics.html, id "analytics"),
Hygiene, Audit, Notifications (notifications.html, id "notifications").
If an item already exists, keep one copy. renderLayout(<id>, …) must highlight the item with that id.
```

**CHECK:** open `index.html?mock=1`; every sidebar item opens its page; the active item is highlighted; no console errors.
`git commit -am "P4 sidebar"`


---
**If the CHECK fails:** use `prompts/99_FIX_template.md`. **Next:** the next numbered file.
