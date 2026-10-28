// static/js/jsonview.js — safe JSON syntax highlighting + console-line helpers (no dependencies)
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
/** Escapes &, <, >, " and ' so the result is safe in element content AND quoted attributes. */
export const escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\b(null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

/** Returns HTML for a pretty-printed, color-highlighted JSON value. Safe for innerHTML. */
export function highlightJson(value, indent = 2) {
  let text;
  try {
    text = JSON.stringify(value, null, indent);
  } catch (e) {
    text = JSON.stringify(String(value));
  }
  if (text === undefined) text = "null";
  let out = "";
  let last = 0;
  for (const m of text.matchAll(TOKEN)) {
    out += escHtml(text.slice(last, m.index));
    let cls = "text-amber-300";                                  // number
    if (m[1]) cls = m[2] ? "text-sky-300" : "text-emerald-300";  // key : string
    else if (m[3]) cls = "text-violet-300";                      // boolean
    else if (m[4]) cls = "text-slate-500";                       // null
    const tok = m[1] || m[3] || m[4] || m[5];
    out += `<span class="${cls}">${escHtml(tok)}</span>` + (m[2] ? escHtml(m[2]) : "");
    last = m.index + m[0].length;
  }
  return out + escHtml(text.slice(last));
}

export const LAYER_STYLE = {
  data: { text: "text-cyan-300", dot: "#22D3EE", label: "Data" },
  detection: { text: "text-fuchsia-300", dot: "#E879F9", label: "Detection" },
  decision: { text: "text-amber-300", dot: "#FBBF24", label: "Decision" },
  learning: { text: "text-emerald-300", dot: "#34D399", label: "Learning" },
  oversight: { text: "text-blue-300", dot: "#60A5FA", label: "Oversight" },
};

export const STATE_STYLE = {
  started: { sym: "▶", cls: "text-sky-400" },
  progress: { sym: "…", cls: "text-slate-400" },
  done: { sym: "✔", cls: "text-emerald-400" },
  failed: { sym: "✖", cls: "text-red-400" },
  threat: { sym: "⚠", cls: "text-red-400" },
  skipped: { sym: "↷", cls: "text-amber-400" },
  info: { sym: "•", cls: "text-slate-400" },
};

/** One console line (HTML) for a trace event. All values escaped. */
export function consoleLine(ev, { showJson = false } = {}) {
  const layer = LAYER_STYLE[ev.layer] || LAYER_STYLE.oversight;
  const st = STATE_STYLE[ev.state] || STATE_STYLE.info;
  const t = new Date(ev.ts);
  const time = isNaN(t) ? "" : t.toLocaleTimeString([], { hour12: false }) + "." + String(t.getMilliseconds()).padStart(3, "0");
  const tag = `[${String(ev.agent_num ?? 0).padStart(2, "0")} ${String(ev.agent_id || "").toUpperCase()}]`;
  const dur = ev.duration_ms != null ? ` <span class="text-slate-500">(${escHtml(Math.round(ev.duration_ms))} ms)</span>` : "";
  const threat = ev.state === "threat";
  const msgCls = threat ? "text-red-300 font-semibold" : ev.state === "failed" ? "text-red-300" : "text-slate-200";
  const badge = threat ? `<span class="mr-2 rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold tracking-wider text-white">THREAT</span>` : "";
  let html = `<div class="cl-line ${threat ? "bg-red-500/10 border-l-2 border-red-500" : "border-l-2 border-transparent"} px-3 py-0.5" data-seq="${escHtml(ev.seq)}">`
    + `<span class="text-slate-500">${escHtml(time)}</span>  `
    + `<span class="${layer.text}">${escHtml(tag.padEnd(24, " "))}</span>`
    + `<span class="${st.cls}">${st.sym}</span>  ${badge}<span class="${msgCls}">${escHtml(ev.message)}</span>${dur}`;
  if (showJson && ev.data != null) {
    html += `<pre class="ml-8 mt-1 mb-2 whitespace-pre-wrap text-[11.5px] leading-5">${highlightJson(ev.data)}</pre>`;
  }
  return html + "</div>";
}
