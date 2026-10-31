# UI_DESIGN.md: IdentityShield "Cream Light" design system

> This file **replaces context.md Section 18** (the old dark "command center" theme). Antigravity: when this file and context.md disagree about colors, theme, 3D or animation, **this file wins**.

---

## 1. Feel

Calm, premium, light. Think of a quiet gallery wall: **uniform creamy white** everywhere, soft pastel accents, gentle depth from shadows instead of glow, and **one beautiful 3D sculpture** as the visual centerpiece. Security alerts stay clearly readable: color is soft, but text contrast is strong.

**Do:**
- cream surfaces
- white cards with soft shadows
- pastel accents
- deep ink text
- small, satisfying 3D motion on buttons

**Don't:**
- dark backgrounds
- neon glow
- busy particle backgrounds
- saturated gradients
- low-contrast grey text on cream

---

## 2. Color tokens (CSS variables in `static/v3/css/theme.css`)

### Base

| Token | Value | Use |
|---|---|---|
| `--bg` | `#FBF8F3` | Page background (creamy white) |
| `--bg-grad` | `linear-gradient(180deg, #FFFDF9 0%, #FBF8F3 55%, #F7F2EA 100%)` | Body background: almost uniform, very soft |
| `--surface` | `#FFFFFF` | Cards, panels, tables |
| `--surface-2` | `#F6F1E9` | Sidebar, table header, inputs, hover rows |
| `--surface-3` | `#EFE8DC` | Pressed states, dividers on surface-2 |
| `--border` | `#E8E1D6` | Card borders, table lines |
| `--ink` | `#1F2430` | Main text (contrast > 12:1 on cream) |
| `--ink-2` | `#4B5263` | Secondary text (≥ 7:1) |
| `--muted` | `#6B7280` | Captions only (≥ 4.5:1 on white); never for important text |
| `--focus` | `#3D6FE0` | Focus ring (2px + 2px offset) |

### Pastel accents (fills, tints, illustrations) and their strong partners (text, icons, borders)

| Name | Pastel fill | Strong (text/icon) | Use |
|---|---|---|---|
| Sky | `#DCE8FF` | `#3D6FE0` | Primary actions, links, brand |
| Mint | `#D9F2EA` | `#0F8A6A` | Success, applied, healthy agents |
| Peach | `#FFE4D3` | `#C2410C` | Restrict band, warnings |
| Butter | `#FFF3C4` | `#A16207` | Step-up band, pending |
| Rose | `#FFE0E0` | `#C81E1E` | Revoke band, threats, errors |
| Lavender | `#ECE6FF` | `#6D4FD8` | ML, insights, predictions |
| Stone | `#EEF0F3` | `#475569` | Monitor band, neutral chips |

**Rule:** a colored badge = pastel background + strong text of the same family (e.g. Rose fill + `#C81E1E` text). Never put white text on a pastel.

### Primary button

- Fill `#3D6FE0` with white text (contrast ≥ 4.5:1).
- Hover `#355FC4`, pressed `#2E54AD`.
- Secondary button: white fill, `--ink` text, `--border` border.
- Danger button: `#C81E1E` fill, white text.

### Band colors (risk)

| Band | Badge fill | Badge text | Gauge/bar color |
|---|---|---|---|
| monitor (<40) | `#EEF0F3` | `#475569` | `#94A3B8` |
| step_up (40–69) | `#FFF3C4` | `#A16207` | `#E0A800` |
| restrict (70–89) | `#FFE4D3` | `#C2410C` | `#F08A4B` |
| revoke (≥90) | `#FFE0E0` | `#C81E1E` | `#E5484D` |

### Chart palette (Chart.js, light background)

Series in this order: `#3D6FE0`, `#0F8A6A`, `#F08A4B`, `#6D4FD8`, `#E0A800`, `#E5484D`. Gridlines `#EFE8DC`, axis text `#4B5263`, tooltip white with `--border` and soft shadow.

---

## 3. Shape, depth, type

| Item | Value |
|---|---|
| Radius | Cards 18px, buttons 12px, inputs 10px, chips 999px |
| Card shadow | `0 1px 2px rgba(31,36,48,.04), 0 8px 24px rgba(31,36,48,.06)` |
| Raised shadow (hover) | `0 2px 4px rgba(31,36,48,.05), 0 16px 40px rgba(31,36,48,.09)` |
| Inset (inputs) | `inset 0 1px 2px rgba(31,36,48,.06)` |
| Font UI | Inter 400/500/600/700 |
| Font data | JetBrains Mono (IDs, JSON, numbers in tables) |
| Sizes | Page title 28/600, section 18/600, body 14/400, caption 12/500 |
| Spacing | 4-px grid; card padding 20–24px; grid gap 20px |
| Motion easing | `cubic-bezier(.2,.8,.2,1)` (out), durations 120–220 ms for UI, 600–900 ms for page-level |

---

## 4. The 3D hero element: "Shield Core" (standalone, on-theme)

A single 3D sculpture that tells the IdentityShield story at a glance. It is a **standalone element in its own card**, not a background effect and not a live data chart. It is themed on our project: a shield protecting an identity, with the 15 agents guarding it.

**Object**
- **Glass shield:** a smooth, rounded shield (extruded from a 2D shield outline with bevelled edges) in **pearlescent glass**: clearcoat, iridescence, soft light transmission, pastel reflections (sky, lavender, peach).
- **Identity core:** inside the shield, a softly glowing **fingerprint disc** (concentric arcs, sky blue on white) or a **keyhole**. A thin horizontal "scan line" sweeps over it every 4 s.
- **15 agent orbs in 5 rings:** small matte spheres on tilted orbits around the shield, colored by layer:
  - Data, 4 orbs: sky
  - Detection, 7 orbs: lavender
  - Decision, 3 orbs: peach
  - Learning, 1 orb: mint
  - Oversight ring: thin butter-colored line, no orbs (the Supervisor)
- **Threat deflection:** every ~8 s a small rose-red particle drifts in from outside; when it reaches the outer ring, the nearest detection orb flashes, the shield shows a soft ripple where it would hit, and the particle bounces away and fades. This is the "story beat": the agents catch it, the shield holds.
- Soft contact shadow under it, so it sits on the cream page. Lighting: neutral studio environment, warm key light, cool rim light.

**Behavior**
- Idle: the shield floats gently (±6 px, 6 s cycle) and turns slowly (±15° side to side); orbs orbit at different speeds per ring.
- Pointer: the whole group tilts toward the cursor (max 10°) with damping; hovering speeds the orbs up slightly.
- Click: a "scan" pulse, where the fingerprint lights up ring by ring (600 ms) and all orbs brighten once.
- Optional live tie-in (only if easy): when the SSE stream reports a new case with band revoke, trigger one threat-deflection beat immediately. This is the only data connection, and the element must work without it.
- Scroll: pause rendering when the card is off-screen.

**Placement**
- Dashboard hero card (right half, about 440×340 px), beside the title "IdentityShield is guarding N identities" and the primary buttons.
- Small static version (200 px, reduced motion style) on empty states ("No cases yet: all identities look normal").
- Never behind text, never full-screen.

**Performance and accessibility**
- Renders only while visible (IntersectionObserver), pauses when the tab is hidden.
- Pixel ratio capped at 2, under 30k triangles, 60 fps target on a laptop.
- `prefers-reduced-motion`: render one still frame, no animation.
- No WebGL: show a static CSS fallback (soft pastel radial blobs in the same colors).
- `aria-hidden="true"`: purely decorative.

---

## 5. 3D micro-animations for buttons

All CSS (plus one tiny JS helper for the tilt and ripple). They must feel **physical and quick**, never bouncy or slow.

| Name | Class | What it does | Use on |
|---|---|---|---|
| **Keycap press** | `.btn-3d` | Button has a 3px darker "base edge" below it (box-shadow). Hover: lifts 1px. Press: moves down 3px and the edge disappears, like a keyboard key. 120 ms. | All primary and danger buttons |
| **Tilt** | `.btn-tilt` | On hover, rotates up to 6° toward the cursor in 3D (perspective 600px), with a soft moving highlight. Resets on leave. | Large CTA buttons ("Run dataset", "Start scan", "Approve") |
| **Shine sweep** | `.btn-shine` | A thin diagonal light band sweeps across once on hover (600 ms). | Primary CTA only |
| **Ripple** | `.btn-ripple` | Soft circular ripple from the click point (pastel of the button's family), 450 ms. | All buttons |
| **Success morph** | `.is-success` state | After a successful action: button briefly turns mint with a drawn check (900 ms), then returns. | Approve, Label, Save |
| **Loading** | `.is-loading` state | Text fades, a small 3D-looking ring spinner appears; button keeps its width. | Any async button |

### Project-themed 3D icon animations (CSS 3D transforms on small inline SVG icons)

Each icon is built from 2–3 SVG layers so parts can move in 3D (`transform-style: preserve-3d`, perspective 300px).

| Icon class | Button(s) | Animation |
|---|---|---|
| `.ico-shield-spin` | Run dataset, Start scan | Shield icon does a 3D Y-axis flip (360°) on hover; on click, a scan line sweeps down over it. |
| `.ico-lock-close` | Approve revoke, Restrict | Padlock: on hover the shackle lifts (translateY −2px, rotateX 20°); on click it drops and "clicks" closed (shackle down, body nudges 1px), then turns mint on success. |
| `.ico-key-turn` | Revoke keys, Rotate secret | Key rotates 90° around its long axis (rotateX) as if turning in a lock, then slides back. |
| `.ico-fingerprint-scan` | Identity, Investigate, open case | Fingerprint arcs light up from center outward (staggered stroke-dashoffset) with a slight 3D tilt toward the cursor. |
| `.ico-radar-sweep` | Live, Refresh, Retro-hunt | A radar wedge rotates once in 3D (slight rotateX tilt so it looks like a dish) on hover; continuous while loading. |
| `.ico-check-draw` | Label TP / FP / Benign, Save | Check mark draws itself (stroke-dashoffset), with a small Z-axis pop (translateZ 6px then back). |
| `.ico-bell-ring` | Notifications, Email admin | Bell swings in 3D (rotateZ ±14° with rotateY 10°) twice. |

All icon animations: 300–600 ms, run once per hover/click (no infinite loops except while loading), same reduced-motion and touch rules as below.

**Rules**
- `prefers-reduced-motion`: keep only color changes; no movement, tilt, sweep or ripple.
- Touch devices: no tilt; press and ripple only.
- Keyboard: `:focus-visible` ring always shown; Enter/Space trigger the same press animation.
- Disabled buttons: no animation, 50 % opacity, `cursor: not-allowed`.

---

## 6. Existing 3D views on a light background

| View | Change |
|---|---|
| Old particle background (`bg3d.js`) | **Remove from pages.** The cream gradient is the background now. Keep the file only if another page imports it, otherwise delete it. |
| Agent constellation (Live page) | Transparent renderer background on a white card; nodes in pastel fills with strong outlines by layer (Data = sky, Detection = lavender, Decision = peach, Learning = mint); running = soft pulse (scale), finding = butter flash, threat = rose ring; message particles in `#3D6FE0` at 70 % opacity; labels in `--ink`. |
| 3D attack graph | Background `#FFFFFF`; node colors from the pastel table with strong-color outlines; links `#CBD5E1`; suspicious path links `#E5484D` with rose particles; Okta→AWS links `#3D6FE0`. |
| Globe | Light globe: ocean `#EEF3FB`, land dots or polygons `#D6DEEA`, atmosphere very light sky; arcs sky blue, impossible-travel arcs rose with animated dashes; points peach. |
| Tables, JSON panels | White cards, `--surface-2` header, JetBrains Mono, JSON syntax colors: keys `#3D6FE0`, strings `#0F8A6A`, numbers `#C2410C`, booleans `#6D4FD8`, null `#6B7280`. |
| Live trace log | Light "terminal": `#FFFDF9` background, `--border`, colored agent tags as pastel chips; THREAT lines with rose fill and strong red text. |
