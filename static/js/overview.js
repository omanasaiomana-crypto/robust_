/**
 * Overview dashboard page: KPIs, attack patterns chart, risk distribution doughnut,
 * top risky identities, and latest critical alerts.
 */
import { api, esc, fmtNum, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, card, errorState, patternChip, riskBar, riskRing, skeleton, statCard, table } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';

const content = renderLayout('overview', 'Threat Overview', 'Real-time multi-agent identity posture');

const scanUrl = isMock ? 'scan.html?mock=1&autostart=replay' : 'scan.html?autostart=1';
const headerActions = document.querySelector('header .flex-shrink-0') || document.getElementById('btn-rerun')?.parentElement;
if (headerActions) {
  const scanBtn = document.createElement('a');
  scanBtn.id = 'btn-run-live-scan';
  scanBtn.href = scanUrl;
  scanBtn.role = 'button';
  scanBtn.className = 'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand hover:bg-blue-500 text-white shadow-sm transition-colors';
  scanBtn.innerHTML = `
    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
    </svg>
    <span>Run live scan</span>
  `;
  scanBtn.onclick = () => { window.location.href = scanUrl; };
  headerActions.appendChild(scanBtn);
}

if (content) {
  content.innerHTML = `
    <!-- Demo Scenario Callout (Visible only for sample data) -->
    <div id="demo-scenario-container"></div>

    <!-- Top Stat Cards Grid -->
    <div id="stats-grid" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      ${skeleton(2)}
      ${skeleton(2)}
      ${skeleton(2)}
      ${skeleton(2)}
    </div>

    <!-- Charts Row -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div id="pattern-chart-card" class="bg-panel border border-line rounded-xl p-5 shadow-sm">
        <h3 class="text-sm font-semibold text-ink mb-4">Alerts by Attack Pattern</h3>
        <div id="pattern-chart-wrapper" class="h-64 flex items-center justify-center">
          ${skeleton(5)}
        </div>
      </div>

      <div id="risk-chart-card" class="bg-panel border border-line rounded-xl p-5 shadow-sm">
        <h3 class="text-sm font-semibold text-ink mb-4">Risk Distribution</h3>
        <div id="risk-chart-wrapper" class="h-64 flex items-center justify-center">
          ${skeleton(5)}
        </div>
      </div>
    </div>

    <!-- Tables Row -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Top Risky Identities Table -->
      <div id="identities-section" class="bg-panel border border-line rounded-xl p-5 shadow-sm">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-sm font-semibold text-ink">Top Risky Identities</h3>
          <a href="/identities.html${querySuffix}" class="text-xs font-medium text-brand hover:text-blue-400 transition-colors">View all →</a>
        </div>
        <div id="identities-wrapper">
          ${skeleton(4)}
        </div>
      </div>

      <!-- Latest Critical Alerts List -->
      <div id="critical-alerts-section" class="bg-panel border border-line rounded-xl p-5 shadow-sm">
        <div class="flex items-center justify-between mb-4">
          <h3 class="text-sm font-semibold text-ink">Latest Critical Alerts (Risk ≥ 70)</h3>
          <a href="/alerts.html?band=revoke${isMock ? '&mock=1' : ''}" class="text-xs font-medium text-brand hover:text-blue-400 transition-colors">Alert queue →</a>
        </div>
        <div id="critical-alerts-wrapper">
          ${skeleton(4)}
        </div>
      </div>
    </div>

    <!-- Which Agents Caught What Attribution Grid -->
    <div class="mt-6 bg-panel border border-line rounded-xl p-5 shadow-sm">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-brand animate-pulse"></span>
            <h3 class="text-sm font-semibold text-ink">Which Agents Caught What (Detection Attribution)</h3>
          </div>
          <p class="text-xs text-muted mt-0.5">Real-time mapping of detection agents to intercepted adversary techniques and affected identities</p>
        </div>
        <div class="flex items-center gap-2">
          <a href="/api/reports/download/docx" download class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-medium transition-colors" title="Download Word report with heatmaps">
            <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
            <span>Download Report (.docx)</span>
          </a>
          <a href="/api/reports/download/html" download class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-400/10 hover:bg-cyan-400/20 text-cyan-300 border border-cyan-400/30 text-xs font-medium transition-colors" title="Download interactive HTML report">
            <span>Interactive (.html)</span>
          </a>
        </div>
      </div>
      <div id="agent-detection-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        ${skeleton(3)}
      </div>
    </div>

    <!-- Live Threat Heatmap Matrix -->
    <div class="mt-6 bg-panel border border-line rounded-xl p-5 shadow-sm">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
        <div>
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-cyan-400"></span>
            <h3 class="text-sm font-semibold text-ink">Identity × Attack Pattern Heatmap Matrix</h3>
          </div>
          <p class="text-xs text-muted mt-0.5">Signal intensity: numbers show detections per vector; red/orange highlight compounded attack profiles</p>
        </div>
        <a href="/analytics.html${querySuffix}" class="text-xs font-medium text-brand hover:text-blue-400 transition-colors">
          Full Analytics & 24h Heatmap →
        </a>
      </div>
      <div id="overview-heatmap-wrapper" class="overflow-x-auto">
        ${skeleton(2)}
      </div>
    </div>
  `;

  loadOverviewData();
}

async function loadOverviewData() {
  const [summaryRes, metricsRes, alertsRes, healthRes, agentMapRes, idHeatmapRes] = await Promise.allSettled([
    api('/summary'),
    api('/metrics'),
    api('/alerts?min_risk=70&limit=5'),
    api('/health'),
    api('/analytics/agent-map'),
    api('/analytics/heatmap/identities'),
  ]);

  const demoContainer = document.getElementById('demo-scenario-container');
  const statsContainer = document.getElementById('stats-grid');
  const patternWrapper = document.getElementById('pattern-chart-wrapper');
  const riskWrapper = document.getElementById('risk-chart-wrapper');
  const identitiesWrapper = document.getElementById('identities-wrapper');
  const alertsWrapper = document.getElementById('critical-alerts-wrapper');

  // Demo Scenario Callout (rendered only when in sample data mode)
  if (demoContainer) {
    const isSampleData = healthRes.status === 'fulfilled' && (healthRes.value?.data_mode === 'sample' || isMock);
    if (isSampleData) {
      demoContainer.innerHTML = `
        <div class="bg-panel border border-brand/40 rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-lg bg-brand/10 border border-brand/30 flex items-center justify-center text-brand font-bold text-base flex-shrink-0">
              ⚡
            </div>
            <div>
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs font-semibold text-ink uppercase tracking-wider">Demo Scenario</span>
                <span class="px-2 py-0.5 rounded text-[11px] font-mono bg-brand/15 text-brand font-medium">Sample data with 5 injected attacks</span>
              </div>
              <p class="text-xs text-muted mt-0.5">
                Explore the critical S3 privilege escalation chain on service account <code class="text-ink font-mono">svc-report</code>.
              </p>
            </div>
          </div>
          <div class="flex items-center gap-2 text-xs flex-wrap">
            <a
              href="/alert.html?id=AL-0001${querySuffix}"
              class="px-3 py-1.5 rounded-lg bg-panel2 border border-line hover:border-brand/50 text-ink hover:text-brand transition-colors font-medium inline-flex items-center gap-1 shadow-sm"
            >
              <span>Alert (AL-0001)</span>
              <span>→</span>
            </a>
            <a
              href="/graph.html?identity=svc-report${querySuffix}"
              class="px-3 py-1.5 rounded-lg bg-panel2 border border-line hover:border-brand/50 text-ink hover:text-brand transition-colors font-medium inline-flex items-center gap-1 shadow-sm"
            >
              <span>Identity Graph</span>
              <span>→</span>
            </a>
            <a
              href="/timeline.html?session=okta:sess-svc-esc-1657${querySuffix}"
              class="px-3 py-1.5 rounded-lg bg-panel2 border border-line hover:border-brand/50 text-ink hover:text-brand transition-colors font-medium inline-flex items-center gap-1 shadow-sm"
            >
              <span>Session Timeline</span>
              <span>→</span>
            </a>
          </div>
        </div>
      `;
    } else {
      demoContainer.innerHTML = '';
    }
  }

  // 1. Stat Cards
  if (summaryRes.status === 'fulfilled') {
    const sum = summaryRes.value;
    const totals = sum.totals || {};
    const byBand = sum.by_band || {};
    const revokeCount = byBand.revoke || 0;
    const topIds = sum.top_identities || [];
    const atRiskCount = topIds.filter((i) => i.risk >= 40).length;

    let f1Value = '—';
    let f1Note = 'Baseline —';
    if (metricsRes.status === 'fulfilled' && metricsRes.value) {
      const m = metricsRes.value;
      if (m.event_f1 !== null && m.event_f1 !== undefined) {
        f1Value = Number(m.event_f1).toFixed(2);
      }
      if (m.baseline_event_f1 !== null && m.baseline_event_f1 !== undefined) {
        f1Note = `Baseline ${Number(m.baseline_event_f1).toFixed(2)}`;
      }
    }

    statsContainer.innerHTML = `
      ${statCard('Total Alerts', fmtNum(totals.alerts || 0), `${fmtNum(totals.events || 0)} events analyzed`)}
      <div class="bg-panel border border-line rounded-xl p-5 shadow-sm flex flex-col justify-between">
        <div class="text-xs uppercase tracking-wide text-muted font-medium mb-1">Critical (Revoke)</div>
        <div class="text-3xl font-semibold tabular-nums text-crit tracking-tight">${fmtNum(revokeCount)}</div>
        <div class="text-xs text-muted mt-2 font-normal">${fmtNum(byBand.restrict || 0)} restrict, ${fmtNum(byBand.step_up || 0)} step-up</div>
      </div>
      ${statCard('Identities at Risk', fmtNum(atRiskCount), `out of ${fmtNum(totals.identities || topIds.length)} identities`)}
      ${statCard('Detection F1 Score', f1Value, f1Note)}
    `;

    // 2. Attack Patterns Bar Chart
    const byPattern = sum.by_pattern || {};
    const patternLabels = [
      'P1 Impossible travel',
      'P2 Dormant account',
      'P3 Privilege escalation',
      'P4 Unusual API',
      'P5 Token abuse',
      'ML Behavior anomaly',
    ];
    const patternCounts = [
      byPattern.P1 || 0,
      byPattern.P2 || 0,
      byPattern.P3 || 0,
      byPattern.P4 || 0,
      byPattern.P5 || 0,
      byPattern.ML || 0,
    ];

    if (window._patternChart) {
      window._patternChart.destroy();
      window._patternChart = null;
    }

    patternWrapper.innerHTML = `<canvas id="canvas-pattern" class="w-full h-full"></canvas>`;
    const patternCanvas = document.getElementById('canvas-pattern');
    if (patternCanvas && window.Chart) {
      window._patternChart = new window.Chart(patternCanvas, {
        type: 'bar',
        data: {
          labels: patternLabels,
          datasets: [
            {
              data: patternCounts,
              backgroundColor: '#3B82F6',
              borderRadius: 4,
              barThickness: 16,
            },
          ],
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#111827',
              borderColor: '#1F2A3C',
              borderWidth: 1,
              titleColor: '#E6EBF2',
              bodyColor: '#8A97AD',
            },
          },
          scales: {
            x: {
              grid: { color: '#1F2A3C' },
              ticks: { color: '#8A97AD', precision: 0, font: { family: 'JetBrains Mono' } },
            },
            y: {
              grid: { display: false },
              ticks: { color: '#E6EBF2', font: { size: 11 } },
            },
          },
        },
      });
    }

    // 3. Risk Distribution Doughnut Chart
    if (window._riskChart) {
      window._riskChart.destroy();
      window._riskChart = null;
    }

    riskWrapper.innerHTML = `<canvas id="canvas-risk" class="w-full h-full"></canvas>`;
    const riskCanvas = document.getElementById('canvas-risk');
    if (riskCanvas && window.Chart) {
      const bandLabels = ['Monitor (<40)', 'Step-up (40-69)', 'Restrict (70-89)', 'Revoke (≥90)'];
      const bandValues = [
        byBand.monitor || 0,
        byBand.step_up || 0,
        byBand.restrict || 0,
        byBand.revoke || 0,
      ];
      const bandColors = ['#94A3B8', '#F59E0B', '#F97316', '#EF4444'];

      window._riskChart = new window.Chart(riskCanvas, {
        type: 'doughnut',
        data: {
          labels: bandLabels,
          datasets: [
            {
              data: bandValues,
              backgroundColor: bandColors,
              borderColor: '#111827',
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '70%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#E6EBF2',
                boxWidth: 12,
                padding: 16,
                font: { size: 11 },
              },
            },
            tooltip: {
              backgroundColor: '#111827',
              borderColor: '#1F2A3C',
              borderWidth: 1,
              titleColor: '#E6EBF2',
              bodyColor: '#8A97AD',
            },
          },
        },
      });
    }

    // 4. Top Risky Identities Table
    const top5Identities = topIds.slice(0, 5);
    if (top5Identities.length === 0) {
      identitiesWrapper.innerHTML = `<p class="text-sm text-muted py-6 text-center">No identities scored yet.</p>`;
    } else {
      const cols = [
        { label: 'Identity' },
        { label: 'Risk Score' },
        { label: 'Alerts', align: 'right' },
        { label: 'Blast Radius', align: 'right' },
      ];
      const rowsHtml = top5Identities
        .map((id) => {
          const band = id.risk >= 90 ? 'revoke' : id.risk >= 70 ? 'restrict' : id.risk >= 40 ? 'step_up' : 'monitor';
          return `
            <tr class="hover:bg-panel2/60 transition-colors">
              <td class="px-4 py-3">
                <a href="/graph.html?identity=${esc(id.identity_id)}${querySuffix}" class="font-medium text-brand hover:underline font-mono text-xs">
                  ${esc(id.identity_id)}
                </a>
              </td>
              <td class="px-4 py-3">
                ${riskBar(id.risk, band)}
              </td>
              <td class="px-4 py-3 text-right tabular-nums text-ink text-xs font-mono">
                ${fmtNum(id.alerts)}
              </td>
              <td class="px-4 py-3 text-right tabular-nums text-muted text-xs font-mono">
                ${fmtNum(id.blast_radius)}
              </td>
            </tr>
          `;
        })
        .join('');
      identitiesWrapper.innerHTML = table(cols, rowsHtml);
    }
  } else {
    statsContainer.innerHTML = errorState(summaryRes.reason?.message || 'Failed to load summary stats');
    patternWrapper.innerHTML = errorState('Failed to load attack pattern distribution');
    riskWrapper.innerHTML = errorState('Failed to load risk distribution');
    identitiesWrapper.innerHTML = errorState('Failed to load top identities');
  }

  // 5. Latest Critical Alerts List
  if (alertsRes.status === 'fulfilled') {
    const alerts = alertsRes.value || [];
    if (alerts.length === 0) {
      alertsWrapper.innerHTML = `<p class="text-sm text-muted py-6 text-center">No high-risk alerts detected.</p>`;
    } else {
      alertsWrapper.innerHTML = `
        <div class="divide-y divide-line">
          ${alerts
            .map((a) => {
              const chipList = a.patterns ? a.patterns.map((p) => patternChip(p)).join(' ') : '';
              return `
                <div class="py-3 flex items-center justify-between gap-4 hover:bg-panel2/40 px-2 rounded-lg transition-colors">
                  <div class="flex items-center gap-3 min-w-0">
                    ${riskRing(a.risk, a.band, 44)}
                    <div class="min-w-0">
                      <div class="flex items-center gap-2">
                        <a href="/alert.html?id=${esc(a.alert_id)}${querySuffix}" class="text-xs font-bold font-mono text-ink hover:text-brand transition-colors">
                          ${esc(a.alert_id)}
                        </a>
                        <span class="text-xs font-mono text-muted">(${esc(a.identity_id)})</span>
                        ${bandBadge(a.band)}
                      </div>
                      <div class="flex items-center gap-1.5 mt-1 overflow-hidden">
                        ${chipList}
                      </div>
                    </div>
                  </div>
                  <div class="text-right flex-shrink-0">
                    <div class="text-[11px] font-mono text-muted">${fmtTime(a.last_seen)}</div>
                    <a href="/alert.html?id=${esc(a.alert_id)}${querySuffix}" class="text-xs font-medium text-brand hover:underline mt-1 inline-block">
                      Investigate →
                    </a>
                  </div>
                </div>
              `;
            })
            .join('')}
        </div>
      `;
    }
  } else {
    alertsWrapper.innerHTML = errorState(alertsRes.reason?.message || 'Failed to load critical alerts');
  }

  // 6. Which Agents Caught What Attribution Grid
  const agentGridWrapper = document.getElementById('agent-detection-grid');
  if (agentGridWrapper) {
    if (agentMapRes.status === 'fulfilled' && agentMapRes.value?.agents) {
      const agents = agentMapRes.value.agents;
      agentGridWrapper.innerHTML = agents
        .map((ag) => {
          const victimTags = ag.victims
            .map(
              (v) =>
                `<a href="/identities.html?search=${esc(v)}" class="px-1.5 py-0.5 rounded bg-panel font-mono text-[11px] text-brand hover:underline">${esc(v)}</a>`
            )
            .join(' ');
          const mitreTags = ag.mitre
            .map(
              (m) =>
                `<span class="px-1.5 py-0.5 rounded bg-panel2 font-mono text-[10px] text-muted border border-line">${esc(m)}</span>`
            )
            .join(' ');
          return `
            <div class="p-3.5 rounded-lg bg-panel2/60 border border-line hover:border-brand/40 transition-colors flex flex-col justify-between">
              <div>
                <div class="flex items-center justify-between gap-2 mb-1.5">
                  <div class="flex items-center gap-1.5 min-w-0">
                    <span class="px-1.5 py-0.5 rounded bg-brand/15 text-brand font-mono text-[10px] font-bold">[${ag.agent_num.toString().padStart(2, '0')}]</span>
                    <span class="text-xs font-bold text-ink truncate">${esc(ag.name)}</span>
                  </div>
                  <span class="px-1.5 py-0.5 rounded-full bg-crit/15 text-crit text-[10px] font-semibold tracking-wider uppercase flex-shrink-0">Caught Threat</span>
                </div>
                <p class="text-[11px] text-muted mt-1 leading-snug">${esc(ag.evidence)}</p>
              </div>
              <div class="mt-3 pt-2.5 border-t border-line/60 flex items-center justify-between gap-2">
                <div class="flex items-center gap-1 flex-wrap">${victimTags}</div>
                <div class="flex items-center gap-1 flex-wrap">${mitreTags}</div>
              </div>
            </div>
          `;
        })
        .join('');
    } else {
      agentGridWrapper.innerHTML = `<p class="text-xs text-muted py-3">Agent map loading or unavailable.</p>`;
    }
  }

  // 7. Identity x Attack Pattern Heatmap Matrix
  const heatmapWrapper = document.getElementById('overview-heatmap-wrapper');
  if (heatmapWrapper) {
    if (idHeatmapRes.status === 'fulfilled' && idHeatmapRes.value?.identities) {
      const hm = idHeatmapRes.value;
      const idents = hm.identities || [];
      const risks = hm.risk || [];
      const patterns = hm.patterns || [];
      const cells = hm.cells || [];

      let tableHtml = `
        <table class="w-full border-collapse text-xs">
          <thead>
            <tr class="border-b border-line text-left text-muted font-mono text-[11px]">
              <th class="py-2.5 px-3 bg-panel2">Identity</th>
              <th class="py-2.5 px-3 bg-panel2 text-center">Risk Score</th>
              ${patterns.map((p) => `<th class="py-2.5 px-3 bg-panel2 text-center font-bold" title="${esc(p)}">${esc(p)}</th>`).join('')}
            </tr>
          </thead>
          <tbody class="divide-y divide-line">
      `;

      idents.forEach((idName, rIdx) => {
        const rVal = risks[rIdx] || 0;
        let riskBadgeClass = 'bg-panel2 text-muted';
        let bandLabel = 'MONITOR';
        if (rVal >= 90) {
          riskBadgeClass = 'bg-crit/20 text-crit border border-crit/40';
          bandLabel = 'REVOKE';
        } else if (rVal >= 70) {
          riskBadgeClass = 'bg-warn/20 text-warn border border-warn/40';
          bandLabel = 'RESTRICT';
        } else if (rVal >= 40) {
          riskBadgeClass = 'bg-cyan-400/20 text-cyan-300 border border-cyan-400/40';
          bandLabel = 'STEP-UP';
        }

        tableHtml += `
          <tr class="hover:bg-panel2/40 transition-colors">
            <td class="py-2 px-3 font-semibold text-ink font-mono">
              <a href="/explorer.html?identity=${esc(idName)}" class="hover:text-brand hover:underline">${esc(idName)}</a>
            </td>
            <td class="py-2 px-3 text-center">
              <span class="px-2 py-0.5 rounded text-[11px] font-bold font-mono ${riskBadgeClass}">
                ${rVal.toFixed(0)} · ${bandLabel}
              </span>
            </td>
        `;

        (cells[rIdx] || []).forEach((val) => {
          let cellCls = 'bg-panel2/40 text-muted/60';
          if (val >= 3) cellCls = 'bg-red-500/35 text-red-300 font-bold';
          else if (val === 2) cellCls = 'bg-orange-500/30 text-orange-200 font-bold';
          else if (val === 1) cellCls = 'bg-amber-400/20 text-amber-200 font-medium';
          tableHtml += `<td class="py-2 px-3 text-center ${cellCls} font-mono">${val}</td>`;
        });

        tableHtml += `</tr>`;
      });

      tableHtml += `</tbody></table>`;
      heatmapWrapper.innerHTML = tableHtml;
    } else {
      heatmapWrapper.innerHTML = `<p class="text-xs text-muted py-3">Heatmap loading or unavailable.</p>`;
    }
  }
}
