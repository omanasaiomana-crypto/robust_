# PHASE 23: Analytics page UI (≈45 min) · Person D

**Why:** the visual answer to "which is better, rules or ML?" and "when are we attacked?". It can be built entirely in mock mode before Phase 22 is live.

Spec: `kit_v2/03_FEATURE_ANALYTICS_SPEC.md` §4. Send the parts one at a time.

## Part A: shell, mocks and sidebar (≈10 min)

```text
Read context.md Section 10 (UI design system) and Sections 16.8–16.9, then
kit_v2/03_FEATURE_ANALYTICS_SPEC.md Section 4.

DO:
1. Create static/mock/analytics_detectors.json, analytics_heatmap_time.json and
   analytics_heatmap_identities.json by copying EXACTLY the JSON blocks in kit_v2/reference/REF_07_mock_json.md.
2. In static/js/api.js, extend the existing mock path table (GET only):
   /analytics/detectors → analytics_detectors, /analytics/heatmap/time → analytics_heatmap_time,
   /analytics/heatmap/identities → analytics_heatmap_identities.
   Query strings must be ignored when matching. Change nothing else in api.js.
3. In static/js/layout.js add a sidebar item "Analytics" (inline SVG bar-chart icon, same style as the
   others) between Identities and Hygiene, linking to analytics.html (keep ?mock=1 like the other links).
4. Create static/analytics.html using EXACTLY the same head and body structure as static/alerts.html
   (same Tailwind config, fonts, app.css), title "IdentityShield · Analytics", with the Chart.js CDN script
   BEFORE the module script /js/analytics.js.
5. Create static/js/analytics.js that only calls renderLayout("analytics", "Detection analytics",
   "Rules vs ML performance and attack activity") and shows skeletons for now.
FILES: static/mock/analytics_*.json, static/js/api.js, static/js/layout.js, static/analytics.html,
static/js/analytics.js
```

CHECK: `analytics.html?mock=1` shows the sidebar with **Analytics** active and the skeletons, with no console errors.

## Part B: comparison section (≈15 min)

```text
Read context.md Section 10 and kit_v2/03_FEATURE_ANALYTICS_SPEC.md Sections 2 and 4.1 (blocks 1–3, 8).
Implement in static/js/analytics.js (use ui.js components and esc() for every value):

Load /analytics/detectors, /analytics/heatmap/time and /analytics/heatmap/identities in parallel with
Promise.allSettled. Each block renders its own skeleton → content / emptyState / errorState independently.

Block 1 · Winner banner: full-width standard card (full border, rounded-xl) containing, on the left, a
4px-wide brand2 accent bar as its own div (flex row; do not use border-left). Check icon +
winner.text (font-medium) + muted line "Session-level comparison · {malicious_sessions} attack sessions".
If labeled is false: neutral card with the note text and an info icon.

Block 2 · Three cards in a responsive grid (1 col mobile, 3 cols lg) for rows with kind "summary"
(rules, ml, hybrid). Each card: label (text-sm text-muted), big F1 (text-4xl font-semibold tabular-nums,
"—" if null), a 4-item mini grid: Precision, Recall, Flagged, False alarms (fp); a thin recall bar
(h-1.5 rounded-full, brand2 fill). The winner card: ring-1 ring-brand2 and a small "Best" pill
(bg-brand2/15 text-brand2). Unlabeled: show only Flagged.

Block 3 · Chart.js grouped bar chart "Precision, recall and F1": labels Rules / ML / Hybrid;
datasets Precision #3B82F6, Recall #22D3EE, F1 #10B981; y min 0 max 1, ticks formatted as 0.0;
grid color #1F2A3C, tick color #8A97AD, legend bottom with #8A97AD labels, borderRadius 4,
maxBarThickness 28; maintainAspectRatio false inside a 260px-high container. Destroy any previous chart
instance before creating. Hide the card when labeled is false. Guard: if typeof Chart === "undefined",
show errorState("Chart library failed to load").

Block 8 · At the bottom: <details> "How we measure" with the definitions table from the spec Section 2,
small muted text.
FILES: static/js/analytics.js
```

CHECK: in mock mode, the banner reads "Hybrid (final alerts) performs best (F1 0.86 …)", three cards show with Hybrid marked **Best**, and the chart renders.

## Part C: heatmaps and agreement (≈20 min)

```text
Read kit_v2/03_FEATURE_ANALYTICS_SPEC.md Sections 4.1 (blocks 4–7) and 4.2 exactly.
Implement in static/js/analytics.js. Write ONE reusable function:

  heatGrid({rowLabels, colLabels, values, max, color, cellText, cellTitle, rowLabelWidth, cellHeight,
            colLabelEvery})

that returns an HTML string using a CSS grid: style="display:grid;grid-template-columns:
<rowLabelWidth> repeat(N, minmax(<min>px, 1fr));gap:2px". The first row is the column labels
(text-[11px] text-muted, centered); each next row is a row label (text-xs, truncate, title=full text)
followed by N cells. Cell style: rounded-[3px], height cellHeight, flex center, text-[11px]
tabular-nums. Zero or empty value → class bg-panel2 and no text (time heatmap) or "0/x" (matrix).
Otherwise background rgba(<color>, a) with a = 0.15 + 0.80 * value / max; text color #0B0F17 if a > 0.55,
else #E6EBF2. Every cell has a title tooltip from cellTitle. All text goes through esc().
Wrap each grid in a div with overflow-x-auto so it scrolls on mobile, never the page.

Block 4 · Card "Which detector catches which attack" (lg:col-span-2): rows = matrix rows (summary rows,
then a 1px divider row using the line color, then detectors); columns = scenarios humanized
(privilege_escalation → "Privilege escalation") + "False alarms". Recall cells: color 34,211,238,
max 1, text "caught/total", title "<row> · <scenario>: caught of total sessions (pct%)".
False alarms column: color 239,68,68, max = max false_alarms (at least 1), text = the count.
Under the grid: a legend "0% → 100% of attack sessions caught" with a small gradient bar.
If labeled is false: emptyState("Labels needed to compare detectors per attack type").

Block 5 · Card "Agreement: rules vs ML" (next to block 4 on lg): a 100%-wide stacked bar of 4 div segments
(rules_only #3B82F6, both #22D3EE, ml_only #A78BFA, missed_by_both #EF4444 at 70% opacity), widths
proportional to counts (skip zero segments), with a legend listing count per segment. Below, one sentence
generated from the numbers, e.g. "ML caught 1 attack session that rules missed; rules caught 3 that ML
missed; 1 attack was missed by both." Use *_true counts when labeled, raw counts otherwise
(and then say "sessions flagged" instead of "attack sessions").

Block 6 · Card "When are we attacked" (full width): subtitle "Events cited as evidence in alerts ·
last {days.length} days · {tz}", total on the right (text-2xl). Rows = days formatted "Tue 27 Oct"
(parse YYYY-MM-DD as a local date, NOT UTC); columns = hours "00".."23", colLabelEvery = 3 when
window.innerWidth < 640 else 1; cellHeight 18px; color 34,211,238; max = data.max; text = count when > 0;
title "Tue 27 Oct, 09:00–10:00: 3 attack events". Below: legend gradient "0 → {max}".
Empty → emptyState("No attack activity in this period").

Block 7 · Card "Identities × detectors" (full width): rows = identities with a small risk number after
the name; columns = pattern codes with title = pattern_names; color 249,115,22 (high orange); max = data.max.
Clicking a row label navigates to graph.html?identity=<id> (keep ?mock=1). Empty → emptyState("No alerts yet").

Layout: blocks 1–3 at top; then a grid lg:grid-cols-3 gap-6 with block 4 (col-span-2) and block 5;
then blocks 6 and 7 stacked; then block 8.
FILES: static/js/analytics.js
```

CHECK (human):
- `analytics.html?mock=1`: all blocks render; the heatmap cells show numbers; hover tooltips work; no horizontal page scroll at 375 px (DevTools); no console errors.
- Without `?mock=1` (backend from Phase 22 running): real data renders.

## Part D: Overview tie-in (≈5 min)

```text
In static/js/overview.js add a compact card "Rules vs ML" after the stat cards: load /analytics/detectors
(inside the existing Promise.allSettled), show winner.text and the three F1 values as small stat items,
plus a link "Open analytics →" to analytics.html (keep ?mock=1). Hide the card when labeled is false or
the request fails. Change nothing else on the page.
FILES: static/js/overview.js
```

---

**After the CHECKs pass:** `git commit -m "phase 23 ok"`, then update context.md Section 20.
