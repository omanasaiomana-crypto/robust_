# PHASE 27: Offline assets: vendor the CDN files (≈15 min) · Person D

**Why:** audit gap 2.4. Venue Wi-Fi fails often. After this phase the console works with the network off.

## Step 1: download the files (human, while online)

From the project root:

**Windows PowerShell** (use `curl.exe`, not the `curl` alias):
```powershell
mkdir static\vendor
curl.exe -L -o static/vendor/tailwind.js https://cdn.tailwindcss.com
curl.exe -L -o static/vendor/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js
curl.exe -L -o static/vendor/vis-network.min.js https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js
```

**macOS / Linux:**
```bash
mkdir -p static/vendor
curl -L -o static/vendor/tailwind.js https://cdn.tailwindcss.com
curl -L -o static/vendor/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js
curl -L -o static/vendor/vis-network.min.js https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js
```

Check the sizes: each file should be well over 50 KB. A tiny file means you saved an error page; download it again.

Fonts are optional: if Google Fonts are unreachable, the pages fall back to the system font and still look clean.

## Step 2: prompt

```text
Read context.md Section 10 and 16.8.
All three vendor files now exist in static/vendor/ (tailwind.js, chart.umd.min.js, vis-network.min.js).
DO:
1. In EVERY static/*.html file, replace:
   https://cdn.tailwindcss.com → /vendor/tailwind.js
   the Chart.js CDN URL → /vendor/chart.umd.min.js
   the vis-network CDN URL → /vendor/vis-network.min.js
   Keep the script order and the inline tailwind.config script exactly as they are (the config must still
   come right AFTER the tailwind script). Keep the Google Fonts <link> tags (they fail harmlessly offline).
2. Add tests/test_vendor.py: for each of the 3 files, assert it exists and is larger than 50_000 bytes;
   with TestClient(app) GET /vendor/tailwind.js returns 200; and no static/*.html still contains
   "cdn.tailwindcss.com", "cdn.jsdelivr.net" or "unpkg.com".
3. Do NOT add static/vendor to .gitignore (the files must be committed so every laptop has them).
FILES: static/*.html, tests/test_vendor.py
```

## CHECK (human)

```bash
pytest -q
```

Then turn **Wi-Fi off**, restart the server, and click through every page. Styling, charts, the graph and the heatmaps must all work. Turn Wi-Fi back on.

---

**After the CHECK passes:** `git commit -m "phase 27 ok"`, then update context.md Section 20.
