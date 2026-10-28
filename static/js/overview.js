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

    <!-- Rules vs ML Compact Card -->
    <div id="analytics-callout-container"></div>

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
  `;

  loadOverviewData();
}

async function loadOverviewData() {
  const [summaryRes, metricsRes, alertsRes, healthRes, analyticsRes] = await Promise.allSettled([
    api('/summary'),
    api('/metrics'),
    api('/alerts?min_risk=70&limit=5'),
    api('/health'),
    api('/analytics/detectors'),
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

    // Rules vs ML compact card
    const analyticsContainer = document.getElementById('analytics-callout-container');
    if (analyticsContainer) {
      if (analyticsRes.status === 'fulfilled' && analyticsRes.value && analyticsRes.value.labeled) {
        const aData = analyticsRes.value;
        const winnerText = aData.winner?.text || 'Detection comparison available';
        const summaryRows = (aData.rows || []).filter((r) => r.kind === 'summary');
        const f1Items = summaryRows
          .map((r) => {
            const val = r.f1 !== null && r.f1 !== undefined ? Number(r.f1).toFixed(2) : '—';
            return `<div class="flex items-center gap-1.5"><span class="text-muted font-medium">${esc(
              r.label.split(' ')[0]
            )}:</span><span class="font-semibold tabular-nums text-ink">${esc(val)}</span></div>`;
          })
          .join('');

        analyticsContainer.innerHTML = `
          <div class="bg-panel border border-brand2/30 rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-brand2/15 border border-brand2/30 flex items-center justify-center text-brand2 font-bold text-sm flex-shrink-0">
                📊
              </div>
              <div>
                <div class="text-xs uppercase tracking-wide text-muted font-semibold">Rules vs ML</div>
                <div class="text-sm font-medium text-ink mt-0.5">${esc(winnerText)}</div>
              </div>
            </div>
            <div class="flex items-center gap-6 flex-wrap">
              <div class="flex items-center gap-4 text-xs font-mono bg-panel2 px-3 py-1.5 rounded-lg border border-line">
                ${f1Items}
              </div>
              <a href="/analytics.html${querySuffix}" class="text-xs font-medium text-brand2 hover:text-cyan-300 transition-colors inline-flex items-center gap-1">
                <span>Open analytics</span>
                <span>→</span>
              </a>
            </div>
          </div>
        `;
      } else {
        analyticsContainer.innerHTML = '';
      }
    }

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
}
