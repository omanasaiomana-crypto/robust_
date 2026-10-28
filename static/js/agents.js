/**
 * Agents dashboard: displays all 15 agents across 5 cooperating layers.
 */
import { api, fmtTime, qs } from './api.js';
import { escHtml, highlightJson, LAYER_STYLE, STATE_STYLE } from './jsonview.js';
import { renderLayout } from './layout.js';
import { errorState, patternChip, skeleton } from './ui.js';

let pollTimer = null;
let currentData = null;
let selectedAgentId = null;
let traceEvents = [];

const LAYERS = [
  { id: 'data', name: 'Data', dot: '#22D3EE', nums: [1, 2, 3, 4] },
  { id: 'detection', name: 'Detection', dot: '#E879F9', nums: [5, 6, 7, 8, 9, 10] },
  { id: 'decision', name: 'Decision', dot: '#FBBF24', nums: [11, 12, 13] },
  { id: 'learning', name: 'Learning', dot: '#34D399', nums: [14] },
  { id: 'oversight', name: 'Oversight', dot: '#60A5FA', nums: [15] },
];

function renderStatePill(state) {
  switch (state) {
    case 'running':
      return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-brand2/15 text-brand2 border border-brand2/30">
        <span class="w-1.5 h-1.5 rounded-full bg-brand2 animate-pulse"></span>Running
      </span>`;
    case 'done':
      return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-ok/15 text-ok border border-ok/30">
        <span class="w-1.5 h-1.5 rounded-full bg-ok"></span>Done
      </span>`;
    case 'failed':
      return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-crit/15 text-crit border border-crit/30">
        <span class="w-1.5 h-1.5 rounded-full bg-crit"></span>Failed
      </span>`;
    case 'skipped':
      return `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-warn/15 text-warn border border-warn/30">
        <span class="w-1.5 h-1.5 rounded-full bg-warn"></span>Skipped
      </span>`;
    case 'waiting':
      return `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-500/15 text-muted border border-slate-500/30">Waiting</span>`;
    case 'idle':
    default:
      return `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-500/15 text-muted border border-slate-500/30">Idle</span>`;
  }
}

function renderBanner(run) {
  const isMock = qs('mock') === '1';
  const querySuffix = isMock ? '?mock=1' : '';
  const completed = run.completed || [];
  const completedCount = completed.length;
  const totalSteps = run.total_steps || 13;
  const progressPct = Math.round((run.progress || 0) * 100);

  const stateLabel = {
    idle: 'Idle',
    running: 'Running…',
    done: 'Complete',
    failed: 'Failed',
  }[run.state] || run.state;

  return `
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm mb-6">
      <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div class="flex items-start sm:items-center gap-3 flex-wrap">
          <div class="w-10 h-10 rounded-xl bg-brand/10 border border-brand/20 flex items-center justify-center text-brand flex-shrink-0">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M3 9h2m-2 6h2m14-6h2m-2 6h2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
            </svg>
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h2 class="text-base font-semibold text-ink">Orchestrator & Supervisor Agent</h2>
              ${renderStatePill(run.state)}
              <span class="font-mono text-xs text-muted bg-panel2 px-2 py-0.5 rounded border border-line">${escHtml(run.run_id || 'no-run')}</span>
              <span class="text-xs uppercase tracking-wide px-2 py-0.5 rounded bg-panel2 text-muted border border-line">${escHtml(run.mode || 'dataset')}</span>
            </div>
            <div class="flex items-center gap-4 mt-2 text-xs text-muted flex-wrap">
              <span>Step <strong class="text-ink">${escHtml(completedCount)}</strong> / ${escHtml(totalSteps)}</span>
              <span>Threats: <strong class="${run.threats > 0 ? 'text-crit font-semibold' : 'text-ink'}">${escHtml(run.threats || 0)}</strong></span>
              <span>Duration: <strong class="text-ink">${run.duration_ms != null ? escHtml(run.duration_ms) + ' ms' : '—'}</strong></span>
            </div>
          </div>
        </div>

        <div class="flex items-center gap-3">
          <a href="/scan.html${querySuffix}" class="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-medium bg-brand hover:bg-blue-600 text-white transition-colors">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Open live scan
          </a>
        </div>
      </div>

      <div class="mt-4 w-full bg-panel2 rounded-full h-1.5 overflow-hidden border border-line">
        <div class="bg-brand h-full transition-all duration-500" style="width: ${progressPct}%"></div>
      </div>
    </div>
  `;
}

function renderAgentCard(agent) {
  const isSelected = selectedAgentId === agent.id;
  const isRunning = agent.state === 'running';
  const isFailed = agent.state === 'failed';

  let borderClasses = 'border-line';
  if (isSelected) {
    borderClasses = 'border-brand ring-1 ring-brand';
  } else if (isRunning) {
    borderClasses = 'border-brand2 ring-1 ring-brand2';
  } else if (isFailed) {
    borderClasses = 'border-crit/60';
  }

  const numStr = String(agent.num).padStart(2, '0');
  const durStr = agent.last_duration_ms != null ? `${Math.round(agent.last_duration_ms)} ms` : '—';
  const runsCount = agent.runs != null ? agent.runs : 0;

  let patternHtml = '';
  if (agent.pattern) {
    patternHtml = `<span class="mt-0.5">${patternChip(agent.pattern)}</span>`;
  }

  let signalsHtml = '';
  if (agent.signals !== null && agent.signals !== undefined) {
    signalsHtml = `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-panel2 text-ink border border-line">${escHtml(agent.signals)} sigs</span>`;
  }

  const permissionsHtml = (agent.permissions || [])
    .slice(0, 2)
    .map(p => `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-panel2 text-muted border border-line">${escHtml(p)}</span>`)
    .join(' ');

  return `
    <button type="button" data-agent-id="${escHtml(agent.id)}"
      class="w-full text-left bg-panel rounded-xl p-4 border ${borderClasses} hover:border-brand/40 transition-all flex flex-col justify-between focus:outline-none focus:ring-1 focus:ring-brand">
      <div>
        <div class="flex items-center justify-between gap-2 mb-1.5">
          <div class="flex items-center gap-1.5">
            <span class="font-mono text-xs font-bold text-muted">${escHtml(numStr)}</span>
            <span class="font-medium text-xs sm:text-sm text-ink truncate">${escHtml(agent.name)}</span>
          </div>
          <div>${renderStatePill(agent.state)}</div>
        </div>

        <p class="text-xs text-muted line-clamp-2 mb-3 leading-relaxed">${escHtml(agent.role || '')}</p>
      </div>

      <div>
        <div class="flex items-center gap-2 flex-wrap mb-2 text-[11px] text-muted">
          <span>${durStr}</span>
          <span>·</span>
          <span>${runsCount} runs</span>
          ${signalsHtml}
          ${patternHtml}
        </div>

        <div class="flex items-center gap-1 flex-wrap">
          ${permissionsHtml}
        </div>

        ${agent.last_error ? `<div class="text-[11px] text-crit mt-2 truncate font-mono">${escHtml(agent.last_error)}</div>` : ''}
      </div>
    </button>
  `;
}

function renderDetail(agent) {
  if (!agent) return '';
  const numStr = String(agent.num).padStart(2, '0');
  const layerStyle = LAYER_STYLE[agent.layer] || LAYER_STYLE.oversight;

  const agentEvents = traceEvents
    .filter(ev => ev.agent_id === agent.id)
    .slice(-10);

  const eventsHtml = agentEvents.length > 0
    ? agentEvents.map(ev => {
        const st = STATE_STYLE[ev.state] || STATE_STYLE.info;
        const tStr = ev.ts ? fmtTime(ev.ts) : '';
        return `
          <div class="flex items-center gap-3 py-1 text-xs border-b border-line/40 last:border-b-0">
            <span class="text-slate-500 font-mono text-[11px]">${escHtml(tStr)}</span>
            <span class="${st.cls} font-mono">${st.sym}</span>
            <span class="text-ink truncate flex-1">${escHtml(ev.message || ev.state)}</span>
            ${ev.duration_ms != null ? `<span class="text-slate-500 font-mono text-[11px]">${Math.round(ev.duration_ms)} ms</span>` : ''}
          </div>
        `;
      }).join('')
    : '<div class="text-xs text-muted py-2">No recent trace events recorded for this agent.</div>';

  return `
    <div class="bg-panel border border-brand/40 rounded-xl p-5 shadow-lg mt-6">
      <div class="flex items-start justify-between gap-4 mb-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-panel2 border border-line flex items-center justify-center font-mono font-bold text-sm text-ink">
            ${escHtml(numStr)}
          </div>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-base font-semibold text-ink">${escHtml(agent.name)}</h3>
              <span class="text-xs font-medium px-2 py-0.5 rounded-full border border-line" style="color: ${layerStyle.dot}">
                ${escHtml(layerStyle.label)}
              </span>
              ${renderStatePill(agent.state)}
            </div>
            <p class="text-xs text-muted mt-1">${escHtml(agent.role || '')}</p>
          </div>
        </div>
        <button id="btn-close-detail" class="p-1 rounded hover:bg-panel2 text-muted hover:text-ink text-sm">✕</button>
      </div>

      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4 text-xs">
        <div class="bg-panel2 p-3 rounded-lg border border-line">
          <div class="text-muted text-[11px] uppercase tracking-wider mb-1">Timing</div>
          <div class="text-ink font-mono">${agent.last_duration_ms != null ? escHtml(agent.last_duration_ms) + ' ms' : '—'}</div>
          <div class="text-muted mt-1">Finished: ${escHtml(fmtTime(agent.last_finished))}</div>
        </div>
        <div class="bg-panel2 p-3 rounded-lg border border-line">
          <div class="text-muted text-[11px] uppercase tracking-wider mb-1">Execution</div>
          <div class="text-ink font-mono">${escHtml(agent.runs ?? 0)} run(s)</div>
          <div class="text-muted mt-1">Started: ${escHtml(fmtTime(agent.last_started))}</div>
        </div>
        <div class="bg-panel2 p-3 rounded-lg border border-line sm:col-span-2">
          <div class="text-muted text-[11px] uppercase tracking-wider mb-1">Permissions</div>
          <div class="flex items-center gap-1.5 flex-wrap mt-1">
            ${(agent.permissions || []).map(p => `<span class="px-2 py-0.5 rounded text-[11px] font-mono bg-panel border border-line text-ink">${escHtml(p)}</span>`).join('')}
          </div>
        </div>
      </div>

      ${agent.last_message ? `
        <div class="mb-4 text-xs">
          <span class="text-muted font-medium">Last status: </span>
          <span class="text-ink font-mono">${escHtml(agent.last_message)}</span>
        </div>
      ` : ''}

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div>
          <div class="text-xs uppercase tracking-wider text-muted font-semibold mb-2">Last Output (JSON)</div>
          <pre class="bg-[#05070C] text-ink p-4 rounded-lg font-mono text-xs max-h-80 overflow-auto border border-line leading-5 whitespace-pre-wrap">${highlightJson(agent.last_output)}</pre>
        </div>

        <div>
          <div class="text-xs uppercase tracking-wider text-muted font-semibold mb-2">Recent Events</div>
          <div class="bg-panel2 p-3 rounded-lg border border-line max-h-80 overflow-auto">
            ${eventsHtml}
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderContent() {
  const container = document.getElementById('agents-container');
  if (!container || !currentData) return;

  const { agents, run } = currentData;
  const agentMap = new Map((agents || []).map(a => [a.num, a]));
  const selectedAgent = selectedAgentId ? (agents || []).find(a => a.id === selectedAgentId) : null;

  let columnsHtml = '';
  LAYERS.forEach((layer, idx) => {
    const layerAgents = layer.nums.map(n => agentMap.get(n)).filter(Boolean);
    const cardsHtml = layerAgents.map(a => renderAgentCard(a)).join('<div class="h-3"></div>');

    columnsHtml += `
      <div class="flex-1 flex flex-col min-w-[240px]">
        <div class="flex items-center justify-between pb-3 mb-3 border-b border-line">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full" style="background-color: ${layer.dot}"></span>
            <h3 class="text-xs font-semibold uppercase tracking-wider text-ink">${escHtml(layer.name)}</h3>
          </div>
          <span class="text-xs font-mono text-muted">${layerAgents.length}</span>
        </div>
        <div class="space-y-3 flex-1">
          ${cardsHtml}
        </div>
      </div>
    `;

    if (idx < LAYERS.length - 1) {
      columnsHtml += `
        <div class="hidden lg:flex items-center justify-center text-muted text-lg select-none px-1">
          ›
        </div>
      `;
    }
  });

  container.innerHTML = `
    ${renderBanner(run || {})}
    <div class="flex flex-col lg:flex-row gap-4 items-stretch overflow-x-auto pb-4">
      ${columnsHtml}
    </div>
    <div id="agent-detail-host">
      ${selectedAgent ? renderDetail(selectedAgent) : ''}
    </div>
  `;

  // Attach card click handlers
  container.querySelectorAll('[data-agent-id]').forEach(btn => {
    btn.addEventListener('click', () => {
      const id = btn.getAttribute('data-agent-id');
      selectedAgentId = selectedAgentId === id ? null : id;
      renderContent();
    });
  });

  const closeBtn = document.getElementById('btn-close-detail');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      selectedAgentId = null;
      renderContent();
    });
  }
}

async function loadData() {
  try {
    const [agentsData, traceData] = await Promise.all([
      api('/agents'),
      api('/scan/trace?after=0&limit=2000').catch(() => ({ events: [] })),
    ]);
    currentData = agentsData;
    traceEvents = (traceData && traceData.events) || [];
    renderContent();

    // Adjust polling interval based on run state
    scheduleNextPoll(currentData.run && currentData.run.state === 'running' ? 1500 : 10000);
  } catch (err) {
    const container = document.getElementById('agents-container');
    if (container && !currentData) {
      container.innerHTML = errorState(err.message || 'Failed to load agents status', 'btn-retry-agents');
      const retryBtn = document.getElementById('btn-retry-agents');
      if (retryBtn) retryBtn.addEventListener('click', loadData);
    }
    scheduleNextPoll(10000);
  }
}

function scheduleNextPoll(delayMs) {
  if (pollTimer) clearTimeout(pollTimer);
  if (document.hidden) return;
  pollTimer = setTimeout(loadData, delayMs);
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    loadData();
  } else if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
});

export async function init() {
  const main = renderLayout('agents', 'Agents', '15 cooperating agents · live status of every layer');
  if (!main) return;

  main.innerHTML = `
    <div id="agents-container" class="max-w-7xl mx-auto">
      ${skeleton(6)}
    </div>
  `;

  await loadData();
}

init();
