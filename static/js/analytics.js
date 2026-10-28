/**
 * Detection analytics: rules vs ML comparison, heatmaps, and agreement.
 */
import { api, esc, qs } from './api.js';
import { card, emptyState, errorState, renderLayout, skeleton } from './ui.js';

let chartInstance = null;

function humanizeScenario(s) {
  if (!s) return 'Unknown';
  return s
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function formatDateRow(ymd) {
  try {
    const parts = ymd.split('-');
    if (parts.length === 3) {
      const d = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]));
      return d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' });
    }
  } catch {
    // fallback
  }
  return ymd;
}

export function heatGrid({
  rowLabels,
  colLabels,
  values,
  max,
  color = '34, 211, 238',
  cellText,
  cellTitle,
  rowLabelWidth = '130px',
  cellHeight = '28px',
  colLabelEvery = 1,
  onRowClick = null,
}) {
  const numCols = colLabels.length;
  const colTemplate = `${rowLabelWidth} repeat(${numCols}, minmax(28px, 1fr))`;

  let html = `<div class="overflow-x-auto"><div style="display:grid;grid-template-columns:${colTemplate};gap:2px;min-width:480px">`;

  // Header row: empty corner + colLabels
  html += `<div></div>`;
  for (let c = 0; c < numCols; c++) {
    const show = c % colLabelEvery === 0;
    const label = show ? esc(colLabels[c]) : '';
    html += `<div class="text-[11px] text-muted text-center py-1 font-mono font-medium">${label}</div>`;
  }

  // Data rows
  const safeMax = max > 0 ? max : 1;
  for (let r = 0; r < rowLabels.length; r++) {
    const rLabel = rowLabels[r];
    const clickAttr = onRowClick ? `data-row-idx="${r}" style="cursor:pointer"` : '';
    html += `<div class="text-xs text-muted truncate pr-2 flex items-center font-medium" title="${esc(
      typeof rLabel === 'object' ? rLabel.title : rLabel
    )}" ${clickAttr}>${typeof rLabel === 'object' ? rLabel.html : esc(rLabel)}</div>`;

    for (let c = 0; c < numCols; c++) {
      const val = values[r] ? values[r][c] : 0;
      const text = cellText ? cellText(r, c, val) : val ? String(val) : '';
      const title = cellTitle ? cellTitle(r, c, val) : '';

      let cellStyle = `height:${cellHeight};`;
      let textClass = 'text-ink';
      let bgClass = 'bg-panel2';

      if (val > 0) {
        const a = Math.min(0.95, 0.15 + (0.8 * val) / safeMax);
        cellStyle += `background-color:rgba(${color}, ${a.toFixed(3)});`;
        textClass = a > 0.55 ? 'text-[#0B0F17] font-semibold' : 'text-[#E6EBF2]';
        bgClass = '';
      }

      html += `<div class="rounded-[3px] flex items-center justify-center text-[11px] tabular-nums font-mono transition-opacity hover:opacity-80 ${bgClass} ${textClass}" style="${cellStyle}" title="${esc(
        title
      )}">${esc(text)}</div>`;
    }
  }

  html += `</div></div>`;
  return html;
}

function renderWinnerBanner(data) {
  if (!data.labeled) {
    return `
      <div class="bg-panel border border-line rounded-xl p-5 shadow-sm flex items-center gap-4">
        <div class="w-1 self-stretch bg-muted/40 rounded-full flex-shrink-0"></div>
        <div class="w-8 h-8 rounded-lg bg-panel2 border border-line flex items-center justify-center text-muted flex-shrink-0">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <div>
          <div class="text-sm font-medium text-ink">${esc(data.note || 'No ground-truth labels available.')}</div>
          <div class="text-xs text-muted mt-0.5">Showing detection counts only.</div>
        </div>
      </div>
    `;
  }

  const winner = data.winner || { text: 'Hybrid (final alerts) performs best', id: 'hybrid' };
  const malSessions = data.malicious_sessions ?? 0;

  return `
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm flex items-center gap-4">
      <div class="w-1 self-stretch bg-brand2 rounded-full flex-shrink-0"></div>
      <div class="w-9 h-9 rounded-lg bg-brand2/15 border border-brand2/30 flex items-center justify-center text-brand2 flex-shrink-0">
        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      </div>
      <div>
        <div class="text-base font-semibold text-ink flex items-center gap-2">
          ${esc(winner.text)}
        </div>
        <div class="text-xs text-muted mt-0.5">
          Session-level comparison · ${esc(malSessions)} attack session${malSessions === 1 ? '' : 's'} · ground-truth labeled
        </div>
      </div>
    </div>
  `;
}

function renderSummaryCards(data) {
  const summaryRows = (data.rows || []).filter((r) => r.kind === 'summary');
  const winnerId = data.winner ? data.winner.id : '';

  return `
    <div class="grid grid-cols-1 md:grid-cols-3 gap-5">
      ${summaryRows
        .map((r) => {
          const isWinner = data.labeled && r.id === winnerId;
          const ringClass = isWinner ? 'ring-1 ring-brand2 border-brand2/40' : 'border-line';
          const f1Str = r.f1 !== null && r.f1 !== undefined ? Number(r.f1).toFixed(2) : '—';
          const precStr = r.precision !== null && r.precision !== undefined ? Number(r.precision).toFixed(2) : '—';
          const recStr = r.recall !== null && r.recall !== undefined ? Number(r.recall).toFixed(2) : '—';
          const recPct = r.recall !== null && r.recall !== undefined ? Math.min(100, Math.round(r.recall * 100)) : 0;

          return `
            <div class="bg-panel border ${ringClass} rounded-xl p-5 shadow-sm flex flex-col justify-between relative">
              <div class="flex items-center justify-between mb-3">
                <span class="text-sm font-semibold text-ink">${esc(r.label)}</span>
                ${
                  isWinner
                    ? `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-brand2/15 text-brand2 border border-brand2/30">Best</span>`
                    : ''
                }
              </div>
              <div class="mb-4">
                <div class="text-xs uppercase tracking-wide text-muted font-medium mb-1">F1 Score</div>
                <div class="text-4xl font-semibold tabular-nums text-ink tracking-tight">${esc(f1Str)}</div>
              </div>
              ${
                data.labeled
                  ? `
                <div class="grid grid-cols-4 gap-2 text-center py-2.5 border-y border-line text-xs mb-3">
                  <div>
                    <div class="text-muted text-[11px]">Precision</div>
                    <div class="font-semibold tabular-nums text-ink mt-0.5">${esc(precStr)}</div>
                  </div>
                  <div>
                    <div class="text-muted text-[11px]">Recall</div>
                    <div class="font-semibold tabular-nums text-ink mt-0.5">${esc(recStr)}</div>
                  </div>
                  <div>
                    <div class="text-muted text-[11px]">Flagged</div>
                    <div class="font-semibold tabular-nums text-ink mt-0.5">${esc(r.flagged)}</div>
                  </div>
                  <div>
                    <div class="text-muted text-[11px]">False Alm</div>
                    <div class="font-semibold tabular-nums text-crit mt-0.5">${esc(r.fp !== null ? r.fp : '—')}</div>
                  </div>
                </div>
                <div>
                  <div class="flex items-center justify-between text-[11px] text-muted mb-1 font-medium">
                    <span>Attack Recall</span>
                    <span class="tabular-nums">${recPct}%</span>
                  </div>
                  <div class="w-full bg-line rounded-full h-1.5 overflow-hidden">
                    <div class="h-full bg-brand2 rounded-full" style="width: ${recPct}%"></div>
                  </div>
                </div>
              `
                  : `
                <div class="py-2 border-t border-line text-xs flex justify-between">
                  <span class="text-muted">Total sessions flagged:</span>
                  <span class="font-semibold tabular-nums text-ink">${esc(r.flagged)}</span>
                </div>
              `
              }
            </div>
          `;
        })
        .join('')}
    </div>
  `;
}

function initComparisonChart(data) {
  const canvas = document.getElementById('chart-comparison');
  if (!canvas) return;

  if (typeof Chart === 'undefined') {
    const parent = canvas.parentElement;
    if (parent) parent.innerHTML = errorState('Chart library failed to load');
    return;
  }

  if (chartInstance) {
    chartInstance.destroy();
    chartInstance = null;
  }

  const summary = (data.rows || []).filter((r) => r.kind === 'summary');
  const labels = summary.map((r) => r.label.split(' ')[0]); // Rules / ML / Hybrid
  const pData = summary.map((r) => (r.precision !== null ? Number(r.precision) : 0));
  const rData = summary.map((r) => (r.recall !== null ? Number(r.recall) : 0));
  const fData = summary.map((r) => (r.f1 !== null ? Number(r.f1) : 0));

  chartInstance = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: 'Precision',
          data: pData,
          backgroundColor: '#3B82F6',
          borderRadius: 4,
          maxBarThickness: 28,
        },
        {
          label: 'Recall',
          data: rData,
          backgroundColor: '#22D3EE',
          borderRadius: 4,
          maxBarThickness: 28,
        },
        {
          label: 'F1 Score',
          data: fData,
          backgroundColor: '#10B981',
          borderRadius: 4,
          maxBarThickness: 28,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#8A97AD',
            font: { family: 'Inter', size: 12 },
            boxWidth: 12,
            boxHeight: 12,
            padding: 16,
          },
        },
        tooltip: {
          backgroundColor: '#161E2E',
          titleColor: '#E6EBF2',
          bodyColor: '#E6EBF2',
          borderColor: '#1F2A3C',
          borderWidth: 1,
          padding: 10,
        },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: '#8A97AD', font: { family: 'Inter', size: 12 } },
        },
        y: {
          min: 0,
          max: 1,
          grid: { color: '#1F2A3C' },
          ticks: {
            color: '#8A97AD',
            font: { family: 'JetBrains Mono', size: 11 },
            callback: (v) => Number(v).toFixed(1),
          },
        },
      },
    },
  });
}

function renderDetectionHeatmap(data) {
  if (!data.labeled || !data.matrix || data.matrix.length === 0) {
    return emptyState('Labels needed to compare detectors per attack type');
  }

  const scenarios = data.scenarios || [];
  const colLabels = [...scenarios.map(humanizeScenario), 'False alarms'];
  const summaryRows = data.matrix.filter((m) => m.kind === 'summary');
  const detectorRows = data.matrix.filter((m) => m.kind === 'detector');

  const allRows = [...summaryRows, ...detectorRows];
  const maxFalseAlarms = Math.max(1, ...allRows.map((r) => r.false_alarms || 0));

  const rowLabels = allRows.map((r) => r.label);
  const values = allRows.map((r) => {
    const scRecalls = (r.cells || []).map((c) => (c.recall !== null && c.recall !== undefined ? c.recall : 0));
    return [...scRecalls, r.false_alarms || 0];
  });

  const cellText = (r, c, val) => {
    if (c === scenarios.length) {
      return String(val); // false alarms count
    }
    const cell = allRows[r].cells[c];
    return cell ? `${cell.caught}/${cell.total}` : '0/0';
  };

  const cellTitle = (r, c, val) => {
    const rowName = allRows[r].label;
    if (c === scenarios.length) {
      return `${rowName} · False alarms: ${val} benign sessions flagged`;
    }
    const cell = allRows[r].cells[c];
    const pct = cell && cell.total > 0 ? Math.round((cell.caught / cell.total) * 100) : 0;
    return `${rowName} · ${humanizeScenario(scenarios[c])}: ${cell ? cell.caught : 0} of ${
      cell ? cell.total : 0
    } sessions (${pct}%)`;
  };

  // Build grid with custom color per column (false alarms column is red)
  // We can render custom grid rows for exact column formatting:
  const colTemplate = `150px repeat(${scenarios.length}, minmax(40px, 1fr)) minmax(44px, 1fr)`;
  let gridHtml = `<div class="overflow-x-auto"><div style="display:grid;grid-template-columns:${colTemplate};gap:2px;min-width:600px">`;

  // Header
  gridHtml += `<div></div>`;
  for (let c = 0; c < colLabels.length; c++) {
    const isFa = c === scenarios.length;
    gridHtml += `<div class="text-[11px] ${
      isFa ? 'text-crit' : 'text-muted'
    } text-center py-1.5 font-medium leading-tight">${esc(colLabels[c])}</div>`;
  }

  allRows.forEach((rObj, rIdx) => {
    // Divider before detector rows
    if (rIdx === summaryRows.length && detectorRows.length > 0) {
      gridHtml += `<div class="col-span-full border-b border-line my-1.5"></div>`;
    }

    gridHtml += `<div class="text-xs text-muted truncate pr-2 flex items-center font-medium" title="${esc(
      rObj.label
    )}">${esc(rObj.label)}</div>`;

    for (let c = 0; c < colLabels.length; c++) {
      const isFa = c === scenarios.length;
      if (isFa) {
        const faVal = rObj.false_alarms || 0;
        let cellStyle = `height:28px;`;
        let textClass = 'text-muted';
        let bgClass = 'bg-panel2';
        if (faVal > 0) {
          const a = Math.min(0.95, 0.15 + (0.8 * faVal) / maxFalseAlarms);
          cellStyle += `background-color:rgba(239, 68, 68, ${a.toFixed(3)});`;
          textClass = a > 0.55 ? 'text-[#0B0F17] font-semibold' : 'text-[#E6EBF2]';
          bgClass = '';
        }
        gridHtml += `<div class="rounded-[3px] flex items-center justify-center text-[11px] tabular-nums font-mono ${bgClass} ${textClass}" style="${cellStyle}" title="${esc(
          cellTitle(rIdx, c, faVal)
        )}">${faVal}</div>`;
      } else {
        const cell = rObj.cells[c];
        const recall = cell && cell.recall !== null && cell.recall !== undefined ? cell.recall : 0;
        let cellStyle = `height:28px;`;
        let textClass = 'text-muted';
        let bgClass = 'bg-panel2';
        if (recall > 0) {
          const a = Math.min(0.95, 0.15 + 0.8 * recall);
          cellStyle += `background-color:rgba(34, 211, 238, ${a.toFixed(3)});`;
          textClass = a > 0.55 ? 'text-[#0B0F17] font-semibold' : 'text-[#E6EBF2]';
          bgClass = '';
        }
        gridHtml += `<div class="rounded-[3px] flex items-center justify-center text-[11px] tabular-nums font-mono ${bgClass} ${textClass}" style="${cellStyle}" title="${esc(
          cellTitle(rIdx, c, recall)
        )}">${cell ? `${cell.caught}/${cell.total}` : '0/0'}</div>`;
      }
    }
  });

  gridHtml += `</div></div>`;

  const legend = `
    <div class="flex items-center justify-between text-xs text-muted mt-4 pt-3 border-t border-line">
      <div class="flex items-center gap-2">
        <span>Recall:</span>
        <div class="w-24 h-2.5 rounded-full" style="background: linear-gradient(to right, rgba(34,211,238,0.15), rgba(34,211,238,0.95))"></div>
        <span>0% → 100% caught</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="w-2.5 h-2.5 rounded-sm bg-crit/70 inline-block"></span>
        <span>False alarms (benign sessions)</span>
      </div>
    </div>
  `;

  return gridHtml + legend;
}

function renderAgreementCard(data) {
  const agr = data.agreement || {};
  const labeled = Boolean(data.labeled);

  const rulesOnly = labeled ? (agr.rules_only_true ?? agr.rules_only ?? 0) : (agr.rules_only ?? 0);
  const both = labeled ? (agr.both_true ?? agr.both ?? 0) : (agr.both ?? 0);
  const mlOnly = labeled ? (agr.ml_only_true ?? agr.ml_only ?? 0) : (agr.ml_only ?? 0);
  const missed = labeled ? (agr.missed_by_both ?? 0) : 0;

  const total = rulesOnly + both + mlOnly + missed;
  const safeTotal = total > 0 ? total : 1;

  const pRules = (rulesOnly / safeTotal) * 100;
  const pBoth = (both / safeTotal) * 100;
  const pMl = (mlOnly / safeTotal) * 100;
  const pMissed = (missed / safeTotal) * 100;

  let sentence = '';
  if (labeled) {
    sentence = `ML caught <b>${mlOnly}</b> attack session${mlOnly === 1 ? '' : 's'} that rules missed; rules caught <b>${rulesOnly}</b> that ML missed; <b>${missed}</b> attack session${missed === 1 ? '' : 's'} missed by both.`;
  } else {
    sentence = `ML flagged <b>${mlOnly}</b> session${mlOnly === 1 ? '' : 's'} that rules missed; rules flagged <b>${rulesOnly}</b> that ML missed; both flagged <b>${both}</b>.`;
  }

  return `
    <div class="space-y-4">
      <div>
        <div class="w-full h-6 rounded-lg overflow-hidden flex bg-panel2 border border-line">
          ${rulesOnly > 0 ? `<div style="width: ${pRules}%" class="bg-[#3B82F6] h-full" title="Rules only: ${rulesOnly}"></div>` : ''}
          ${both > 0 ? `<div style="width: ${pBoth}%" class="bg-[#22D3EE] h-full" title="Both detectors: ${both}"></div>` : ''}
          ${mlOnly > 0 ? `<div style="width: ${pMl}%" class="bg-[#A78BFA] h-full" title="ML only: ${mlOnly}"></div>` : ''}
          ${missed > 0 ? `<div style="width: ${pMissed}%" class="bg-[#EF4444]/70 h-full" title="Missed by both: ${missed}"></div>` : ''}
        </div>
      </div>
      <div class="grid grid-cols-2 gap-2 text-xs">
        <div class="flex items-center gap-1.5">
          <span class="w-3 h-3 rounded-sm bg-[#3B82F6] flex-shrink-0"></span>
          <span class="text-muted">Rules only: <b class="text-ink">${rulesOnly}</b></span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="w-3 h-3 rounded-sm bg-[#22D3EE] flex-shrink-0"></span>
          <span class="text-muted">Both: <b class="text-ink">${both}</b></span>
        </div>
        <div class="flex items-center gap-1.5">
          <span class="w-3 h-3 rounded-sm bg-[#A78BFA] flex-shrink-0"></span>
          <span class="text-muted">ML only: <b class="text-ink">${mlOnly}</b></span>
        </div>
        ${
          labeled
            ? `
          <div class="flex items-center gap-1.5">
            <span class="w-3 h-3 rounded-sm bg-[#EF4444]/70 flex-shrink-0"></span>
            <span class="text-muted">Missed: <b class="text-ink">${missed}</b></span>
          </div>
        `
            : ''
        }
      </div>
      <p class="text-xs text-muted leading-relaxed pt-2 border-t border-line">${sentence}</p>
    </div>
  `;
}

function renderTimeHeatmap(data) {
  if (!data || !data.days || data.days.length === 0 || (data.total || 0) === 0) {
    return emptyState('No attack activity in this period');
  }

  const days = data.days;
  const hours = data.hours || Array.from({ length: 24 }, (_, i) => i);
  const colLabels = hours.map((h) => String(h).padStart(2, '0'));
  const rowLabels = days.map(formatDateRow);
  const values = data.cells || [];
  const maxVal = data.max || 1;
  const colEvery = window.innerWidth < 640 ? 3 : 1;

  const cellText = (r, c, val) => (val > 0 ? String(val) : '');
  const cellTitle = (r, c, val) => {
    const dStr = rowLabels[r];
    const h = String(hours[c]).padStart(2, '0');
    const hNext = String((hours[c] + 1) % 24).padStart(2, '0');
    return `${dStr}, ${h}:00–${hNext}:00 ${data.tz || ''}: ${val} attack event${val === 1 ? '' : 's'}`;
  };

  const gridHtml = heatGrid({
    rowLabels,
    colLabels,
    values,
    max: maxVal,
    color: '34, 211, 238',
    cellText,
    cellTitle,
    rowLabelWidth: '100px',
    cellHeight: '18px',
    colLabelEvery: colEvery,
  });

  const legend = `
    <div class="flex items-center justify-between text-xs text-muted mt-4 pt-3 border-t border-line">
      <div class="flex items-center gap-2">
        <span>Activity:</span>
        <div class="w-24 h-2.5 rounded-full" style="background: linear-gradient(to right, rgba(34,211,238,0.15), rgba(34,211,238,0.95))"></div>
        <span>0 → ${data.max} events</span>
      </div>
      <span>Hour of day (${esc(data.tz || 'UTC')})</span>
    </div>
  `;

  return gridHtml + legend;
}

function renderIdentitiesHeatmap(data) {
  if (!data || !data.identities || data.identities.length === 0) {
    return emptyState('No alerts yet');
  }

  const isMock = qs('mock') === '1';
  const querySuffix = isMock ? '&mock=1' : '';

  const identities = data.identities;
  const patterns = data.patterns || [];
  const patternNames = data.pattern_names || [];
  const riskList = data.risk || [];
  const maxVal = data.max || 1;

  const rowLabels = identities.map((id, idx) => {
    const risk = riskList[idx] !== undefined ? riskList[idx] : '—';
    const href = `/graph.html?identity=${encodeURIComponent(id)}${querySuffix}`;
    return {
      title: `${id} (risk: ${risk})`,
      html: `<a href="${href}" class="hover:text-brand2 transition-colors flex items-center truncate">
        <span class="truncate">${esc(id)}</span>
        <span class="text-muted font-mono ml-1.5 flex-shrink-0 text-[10px]">(${risk})</span>
      </a>`,
    };
  });

  const cellText = (r, c, val) => (val > 0 ? String(val) : '');
  const cellTitle = (r, c, val) => {
    const pName = patternNames[c] || patterns[c];
    return `${identities[r]} · ${patterns[c]} (${pName}): ${val} signal${val === 1 ? '' : 's'}`;
  };

  const gridHtml = heatGrid({
    rowLabels,
    colLabels: patterns,
    values: data.cells || [],
    max: maxVal,
    color: '249, 115, 22',
    cellText,
    cellTitle,
    rowLabelWidth: '160px',
    cellHeight: '26px',
    colLabelEvery: 1,
  });

  const legend = `
    <div class="flex items-center justify-between text-xs text-muted mt-4 pt-3 border-t border-line">
      <div class="flex items-center gap-2">
        <span>Signal density:</span>
        <div class="w-24 h-2.5 rounded-full" style="background: linear-gradient(to right, rgba(249,115,22,0.15), rgba(249,115,22,0.95))"></div>
        <span>0 → ${data.max} signals</span>
      </div>
      <span>Click identity to view Attack Graph</span>
    </div>
  `;

  return gridHtml + legend;
}

function renderDefinitionsTable() {
  return `
    <details class="bg-panel border border-line rounded-xl p-4 text-xs text-muted transition-colors">
      <summary class="font-medium text-ink cursor-pointer hover:text-brand2 transition-colors flex items-center justify-between">
        <span>How we measure (Session-level evaluation definitions)</span>
        <svg class="w-4 h-4 text-muted transform group-open:rotate-180 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
        </svg>
      </summary>
      <div class="mt-4 pt-3 border-t border-line overflow-x-auto">
        <table class="w-full text-left border-collapse text-xs">
          <thead>
            <tr class="border-b border-line text-muted">
              <th class="py-2 pr-4 font-semibold uppercase tracking-wider">Term</th>
              <th class="py-2 font-semibold uppercase tracking-wider">Definition</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-line text-ink">
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Attack session</td>
              <td class="py-2 text-muted">A session containing at least one event whose label is not <code class="text-ink">benign</code>.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Scenario</td>
              <td class="py-2 text-muted">The attack label (e.g. <code class="text-ink">privilege_escalation</code>); a session can contain multiple attack scenarios.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Rules flagged</td>
              <td class="py-2 text-muted">Sessions with at least one P1–P5 rule signal.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">ML flagged</td>
              <td class="py-2 text-muted">Sessions with an ML signal (Isolation Forest anomaly score ≥ 0.60).</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Hybrid flagged</td>
              <td class="py-2 text-muted">Sessions with a final alert at risk ≥ 40 (step-up band or higher).</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Precision</td>
              <td class="py-2 text-muted">Flagged attack sessions ÷ all flagged sessions.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Recall</td>
              <td class="py-2 text-muted">Flagged attack sessions ÷ all attack sessions.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">F1 Score</td>
              <td class="py-2 text-muted">Harmonic mean of precision and recall: 2 × P × R ÷ (P + R).</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Recall per scenario</td>
              <td class="py-2 text-muted">Sessions of that scenario flagged by detector ÷ all sessions of that scenario.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">False alarms</td>
              <td class="py-2 text-muted">Flagged sessions that do not contain any attack event.</td>
            </tr>
            <tr>
              <td class="py-2 pr-4 font-mono font-medium text-brand2">Winner</td>
              <td class="py-2 text-muted">Highest F1 among Rules, ML, and Hybrid; ties resolved by precision, then recall.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </details>
  `;
}

export async function initAnalytics() {
  const container = renderLayout(
    'analytics',
    'Detection analytics',
    'Rules vs ML performance, attack-activity heatmaps, and agreement'
  );
  if (!container) return;

  // Render initial skeletons layout
  container.innerHTML = `
    <div class="space-y-6">
      <div id="block-winner">${skeleton(2)}</div>
      <div id="block-summary">${skeleton(4)}</div>
      <div id="block-chart" class="hidden"></div>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div id="block-heatmap-detectors" class="lg:col-span-2">${skeleton(6)}</div>
        <div id="block-agreement">${skeleton(6)}</div>
      </div>
      <div id="block-heatmap-time">${skeleton(5)}</div>
      <div id="block-heatmap-identities">${skeleton(5)}</div>
      <div id="block-definitions">${renderDefinitionsTable()}</div>
    </div>
  `;

  // Fetch all 3 endpoints in parallel
  const [detResult, timeResult, idResult] = await Promise.allSettled([
    api.get('/analytics/detectors'),
    api.get('/analytics/heatmap/time'),
    api.get('/analytics/heatmap/identities'),
  ]);

  // 1. Detectors comparison (Blocks 1, 2, 3, 4, 5)
  const elWinner = document.getElementById('block-winner');
  const elSummary = document.getElementById('block-summary');
  const elChart = document.getElementById('block-chart');
  const elHmDet = document.getElementById('block-heatmap-detectors');
  const elAgr = document.getElementById('block-agreement');

  if (detResult.status === 'fulfilled' && detResult.value) {
    const detData = detResult.value;

    if (elWinner) elWinner.innerHTML = renderWinnerBanner(detData);
    if (elSummary) elSummary.innerHTML = renderSummaryCards(detData);

    // Grouped bar chart
    if (elChart) {
      if (detData.labeled) {
        elChart.classList.remove('hidden');
        elChart.innerHTML = card(
          'Precision, recall and F1 comparison',
          `<div class="h-[260px] relative"><canvas id="chart-comparison"></canvas></div>`
        );
        setTimeout(() => initComparisonChart(detData), 50);
      } else {
        elChart.classList.add('hidden');
      }
    }

    // Block 4: Which detector catches which attack
    if (elHmDet) {
      elHmDet.innerHTML = card(
        'Which detector catches which attack',
        renderDetectionHeatmap(detData),
        `<span class="text-xs text-muted">Recall per scenario</span>`
      );
    }

    // Block 5: Agreement rules vs ML
    if (elAgr) {
      elAgr.innerHTML = card(
        'Agreement: rules vs ML',
        renderAgreementCard(detData),
        `<span class="text-xs text-muted">Session overlap</span>`
      );
    }
  } else {
    const err = detResult.reason?.message || 'Failed to load detector comparison';
    if (elWinner) elWinner.innerHTML = errorState(err);
    if (elSummary) elSummary.innerHTML = '';
    if (elHmDet) elHmDet.innerHTML = card('Which detector catches which attack', errorState(err));
    if (elAgr) elAgr.innerHTML = card('Agreement: rules vs ML', errorState(err));
  }

  // 2. Attack time heatmap (Block 6)
  const elTime = document.getElementById('block-heatmap-time');
  if (elTime) {
    if (timeResult.status === 'fulfilled' && timeResult.value) {
      const tData = timeResult.value;
      const subtitle = `Events cited as evidence in alerts · last ${(tData.days || []).length} days · ${esc(
        tData.tz || 'UTC'
      )}`;
      const totalHtml = `<div class="text-right"><div class="text-xs text-muted uppercase">Total events</div><div class="text-2xl font-semibold tabular-nums text-ink">${tData.total ?? 0}</div></div>`;
      elTime.innerHTML = card(
        'When are we attacked',
        `
          <p class="text-xs text-muted mb-4">${subtitle}</p>
          ${renderTimeHeatmap(tData)}
        `,
        totalHtml
      );
    } else {
      elTime.innerHTML = card(
        'When are we attacked',
        errorState(timeResult.reason?.message || 'Failed to load attack time heatmap')
      );
    }
  }

  // 3. Identity x detector heatmap (Block 7)
  const elId = document.getElementById('block-heatmap-identities');
  if (elId) {
    if (idResult.status === 'fulfilled' && idResult.value) {
      const idData = idResult.value;
      elId.innerHTML = card(
        'Identities × detectors',
        `
          <p class="text-xs text-muted mb-4">Top identities by risk × detection pattern signal count</p>
          ${renderIdentitiesHeatmap(idData)}
        `
      );
    } else {
      elId.innerHTML = card(
        'Identities × detectors',
        errorState(idResult.reason?.message || 'Failed to load identity pattern heatmap')
      );
    }
  }
}

// Auto-run on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAnalytics);
} else {
  initAnalytics();
}
