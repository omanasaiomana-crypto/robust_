// static/js/graphfx.js — attack-path logic + canvas effects for the Identity Graph (vis-network 9)
// Pure functions are unit-tested; drawing helpers only use the standard Canvas 2D API.

/** Readable names for graph edge labels that are not escalation-chain steps. [action, state] */
export const FRIENDLY = {
  login: ["Okta login", "InitialAccess"], created_key: ["Created access key", "CredCreate"],
  attached: ["Attached policy", "PermGrant"], assumed: ["Assumed role", "RoleAssume"],
  accessed: ["Accessed resource", "Impact"], uses_key: ["Used access key", "CredUse"],
};

/** Ordered attack path from graph edges and an alert.
 * Order = alert.evidence_event_ids (already sorted by time), then chain ids not in the evidence.
 * Context edges (e.g. from_ip) are not steps. Returns edge indexes, ordered node ids and step details. */
export function computeAttackPath(edges, alert, { skipLabels = ["from_ip"] } = {}) {
  const order = [];
  for (const id of (alert && alert.evidence_event_ids) || []) if (id && !order.includes(id)) order.push(id);
  for (const s of (alert && alert.chain) || []) if (s && s.event_id && !order.includes(s.event_id)) order.push(s.event_id);
  const rank = new Map(order.map((id, i) => [id, i]));
  const steps = [];
  (edges || []).forEach((e, index) => {
    if (e && e.event_id != null && rank.has(e.event_id) && !skipLabels.includes(e.label)) {
      steps.push({ index, rank: rank.get(e.event_id), ...e });
    }
  });
  steps.sort((a, b) => a.rank - b.rank || a.index - b.index);
  const chainByEvent = new Map(((alert && alert.chain) || []).map((s) => [s.event_id, s]));
  const nodeIds = [];
  for (const s of steps) for (const n of [s.source, s.target]) if (!nodeIds.includes(n)) nodeIds.push(n);
  return {
    edgeIndexes: steps.map((s) => s.index),
    nodeIds,
    steps: steps.map((s, i) => ({
      step: i + 1, edgeIndex: s.index, from: s.source, to: s.target, label: s.label, event_id: s.event_id,
      state: chainByEvent.get(s.event_id)?.state ?? FRIENDLY[s.label]?.[1] ?? null,
      action: chainByEvent.get(s.event_id)?.action ?? FRIENDLY[s.label]?.[0] ?? s.label,
      timestamp: chainByEvent.get(s.event_id)?.timestamp ?? null,
    })),
  };
}

/** Directed BFS: node ids reachable from start within maxDepth hops (start excluded). */
export function reachable(edges, start, maxDepth = 6) {
  const out = new Map();
  for (const e of edges || []) {
    if (!out.has(e.source)) out.set(e.source, []);
    out.get(e.source).push(e.target);
  }
  const seen = new Set([start]);
  let frontier = [start];
  for (let d = 0; d < maxDepth && frontier.length; d++) {
    const next = [];
    for (const n of frontier) for (const m of out.get(n) || []) if (!seen.has(m)) { seen.add(m); next.push(m); }
    frontier = next;
  }
  seen.delete(start);
  return seen;
}

/** Minutes between first and last timestamped step, or null. */
export function pathDurationMinutes(steps) {
  const ts = (steps || []).map((s) => Date.parse(s.timestamp)).filter((n) => !isNaN(n));
  if (ts.length < 2) return null;
  return Math.round((Math.max(...ts) - Math.min(...ts)) / 60000);
}

/** Moving glowing particles along each [fromId, toId] pair. Call from network.on("afterDrawing"). */
export function drawFlow(ctx, pairs, positions, t, { color = "#EF4444", count = 3, radius = 3.2, period = 1400 } = {}) {
  ctx.save();
  for (let i = 0; i < pairs.length; i++) {
    const a = positions[pairs[i][0]], b = positions[pairs[i][1]];
    if (!a || !b) continue;
    for (let k = 0; k < count; k++) {
      const p = (t / period + k / count + i * 0.17) % 1;
      ctx.beginPath();
      ctx.arc(a.x + (b.x - a.x) * p, a.y + (b.y - a.y) * p, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.shadowColor = color;
      ctx.shadowBlur = 14;
      ctx.fill();
    }
  }
  ctx.restore();
}

/** Numbered step badges above path nodes (1, 2, 3 …). upto limits how many are shown (playback). */
export function drawStepBadges(ctx, nodeIds, positions, { upto = Infinity, color = "#EF4444" } = {}) {
  ctx.save();
  ctx.font = "600 11px Inter, system-ui, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  nodeIds.slice(0, Math.min(nodeIds.length, upto)).forEach((id, i) => {
    const p = positions[id];
    if (!p) return;
    const x = p.x + 16, y = p.y - 18;
    ctx.beginPath();
    ctx.arc(x, y, 9, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.lineWidth = 2;
    ctx.strokeStyle = "#0B0F17";
    ctx.stroke();
    ctx.fillStyle = "#FFFFFF";
    ctx.fillText(String(i + 1), x, y + 0.5);
  });
  ctx.restore();
}

/** Pulsing dashed ring around the identity (blast radius halo). */
export function drawHalo(ctx, position, t, { radius = 46, color = "rgba(249,115,22,0.85)" } = {}) {
  if (!position) return;
  ctx.save();
  ctx.setLineDash([6, 6]);
  ctx.lineDashOffset = -(t / 40) % 12;
  ctx.lineWidth = 2;
  ctx.strokeStyle = color;
  ctx.beginPath();
  ctx.arc(position.x, position.y, radius + Math.sin(t / 450) * 3, 0, Math.PI * 2);
  ctx.stroke();
  ctx.restore();
}
