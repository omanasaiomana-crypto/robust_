/**
 * Session Timeline page: step-by-step interactive attack replay.
 * Features playback controls (play/pause, speed toggle, step slider),
 * vertical event stream, dimming of unreached events, current step highlighting,
 * auto-scrolling into view, and embedded signal callouts.
 */
import { api, esc, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import { emptyState, errorState, mitreChip, patternChip, skeleton } from './ui.js';

const isMock = qs('mock') === '1';
const querySuffix = isMock ? '?mock=1' : '';
let sessionParam = qs('session');

// Root container layout
const content = renderLayout('timeline', 'Session Timeline', 'Step-by-step session attack activity replay');

if (content) {
  content.innerHTML = `
    <!-- Top Breadcrumbs & Session Info -->
    <div id="timeline-header-bar" class="flex items-center justify-between gap-4 flex-wrap pb-1">
      <div class="flex items-center gap-3">
        <a href="/alerts.html${querySuffix}" class="text-xs font-medium text-brand hover:underline">
          ← Back to Alerts
        </a>
        <span class="text-muted">•</span>
        <span id="session-display" class="text-xs font-mono text-muted">
          Session: <strong class="text-ink">${esc(sessionParam || 'Loading...')}</strong>
        </span>
      </div>
      <div id="timeline-stats-badge" class="text-xs text-muted font-medium flex items-center gap-3">
        <!-- populated dynamically -->
      </div>
    </div>

    <!-- Timeline Controller Card -->
    <div id="timeline-controls-card" class="bg-panel border border-line rounded-xl p-4 shadow-sm space-y-4">
      <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
        <!-- Play / Pause & Step Navigation Buttons -->
        <div class="flex items-center gap-2 w-full sm:w-auto">
          <button
            id="btn-play-pause"
            class="px-4 py-2 rounded-lg text-xs font-semibold bg-brand hover:bg-blue-500 text-white flex items-center gap-2 shadow-sm transition-colors"
            title="Play / Pause timeline playback"
          >
            <span id="play-pause-icon">▶</span>
            <span id="play-pause-text">Play</span>
          </button>

          <button
            id="btn-step-prev"
            class="px-3 py-2 rounded-lg text-xs font-medium bg-panel2 border border-line hover:bg-line text-ink transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="Previous step (Left Arrow)"
          >
            ← Prev
          </button>

          <button
            id="btn-step-next"
            class="px-3 py-2 rounded-lg text-xs font-medium bg-panel2 border border-line hover:bg-line text-ink transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="Next step (Right Arrow)"
          >
            Next →
          </button>

          <!-- Step Counter Badge -->
          <div id="step-counter" class="text-xs font-mono text-muted px-2 py-1 bg-panel2/60 border border-line rounded-lg">
            Step <strong id="step-current" class="text-ink">1</strong> of <strong id="step-total" class="text-ink">0</strong>
          </div>
        </div>

        <!-- Speed & Jump Controls -->
        <div class="flex items-center gap-3 w-full sm:w-auto justify-end">
          <label for="speed-select" class="text-xs text-muted font-medium">Speed:</label>
          <select
            id="speed-select"
            class="bg-panel2 border border-line rounded-lg px-2.5 py-1.5 text-xs font-mono text-ink focus:border-brand focus:outline-none"
          >
            <option value="1000">1x (1.0s)</option>
            <option value="500">2x (0.5s)</option>
          </select>

          <button
            id="btn-jump-first"
            class="text-xs text-muted hover:text-ink px-2 py-1 rounded bg-panel2/40 border border-line hover:bg-panel2 transition-colors"
            title="Jump to first step"
          >
            Reset
          </button>
        </div>
      </div>

      <!-- Scrubber Range Slider -->
      <div class="space-y-1">
        <div class="flex justify-between text-[11px] font-mono text-muted">
          <span>Start of session</span>
          <span id="slider-time-label">—</span>
          <span>End of session</span>
        </div>
        <input
          id="timeline-slider"
          type="range"
          min="0"
          max="0"
          value="0"
          class="w-full accent-brand h-2 bg-panel2 rounded-lg cursor-pointer transition-all"
        />
      </div>
    </div>

    <!-- Timeline Events Container -->
    <div id="timeline-events-container" class="relative">
      ${skeleton(6)}
    </div>
  `;

  initTimeline();
}

async function resolveSessionId() {
  if (sessionParam) return sessionParam;

  if (isMock) {
    sessionParam = 'okta:sess-svc-esc-1657';
    return sessionParam;
  }

  // Live mode: fetch first alert to determine active session ID
  try {
    const alerts = await api('/alerts');
    if (alerts && alerts.length > 0) {
      sessionParam = alerts[0].session_id || 'okta:sess-svc-esc-1657';
      return sessionParam;
    }
  } catch (err) {
    console.warn('Failed to fetch default session from /alerts:', err);
  }

  sessionParam = 'okta:sess-svc-esc-1657';
  return sessionParam;
}

async function initTimeline() {
  const container = document.getElementById('timeline-events-container');
  const sessionDisplay = document.getElementById('session-display');
  const statsBadge = document.getElementById('timeline-stats-badge');
  const playPauseBtn = document.getElementById('btn-play-pause');
  const playPauseIcon = document.getElementById('play-pause-icon');
  const playPauseText = document.getElementById('play-pause-text');
  const prevBtn = document.getElementById('btn-step-prev');
  const nextBtn = document.getElementById('btn-step-next');
  const slider = document.getElementById('timeline-slider');
  const stepCurrentEl = document.getElementById('step-current');
  const stepTotalEl = document.getElementById('step-total');
  const speedSelect = document.getElementById('speed-select');
  const jumpFirstBtn = document.getElementById('btn-jump-first');
  const sliderTimeLabel = document.getElementById('slider-time-label');

  try {
    const activeSessionId = await resolveSessionId();
    if (sessionDisplay) {
      sessionDisplay.innerHTML = `Session: <strong class="text-ink">${esc(activeSessionId)}</strong>`;
    }

    const items = await api(`/sessions/${encodeURIComponent(activeSessionId)}/timeline`);

    if (!items || items.length === 0) {
      if (container) {
        container.innerHTML = emptyState(`No events recorded for session ${activeSessionId}.`);
      }
      return;
    }

    const totalEvents = items.length;
    let currentStep = 0;
    let isPlaying = false;
    let playTimer = null;

    // Total signals count
    const totalSignals = items.reduce((sum, it) => sum + (it.signals ? it.signals.length : 0), 0);
    const affectedIdentity = items[0]?.event?.identity_id || 'Unknown';

    if (statsBadge) {
      statsBadge.innerHTML = `
        <span class="font-mono text-ink font-semibold">${totalEvents}</span> events
        <span>•</span>
        <span class="font-mono text-crit font-semibold">${totalSignals}</span> signals
        <span>•</span>
        <span class="font-mono text-brand">${esc(affectedIdentity)}</span>
      `;
    }

    if (slider) {
      slider.max = String(totalEvents - 1);
      slider.value = '0';
    }
    if (stepTotalEl) stepTotalEl.textContent = String(totalEvents);
    if (stepCurrentEl) stepCurrentEl.textContent = '1';

    // Render Events List markup
    const eventsHtml = items
      .map((item, idx) => {
        const ev = item.event || {};
        const signals = item.signals || [];
        const isOkta = ev.source === 'okta';
        const isSuccess = (ev.outcome || '').toLowerCase() === 'success';

        const sourceBadge = isOkta
          ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-blue-950/60 border border-blue-800/50 text-blue-400">Okta</span>`
          : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-950/60 border border-amber-800/50 text-amber-400">CloudTrail</span>`;

        const outcomeBadge = isSuccess
          ? `<span class="inline-flex items-center gap-1 text-[11px] font-mono font-medium text-ok"><span>✓</span> success</span>`
          : `<span class="inline-flex items-center gap-1 text-[11px] font-mono font-medium text-crit"><span>✗</span> ${esc(ev.outcome || 'failed')}</span>`;

        const signalsHtml =
          signals.length > 0
            ? `
              <div class="mt-3 pt-3 border-t border-line/60 space-y-2">
                <div class="text-[10px] font-mono uppercase tracking-wider text-crit font-bold flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full bg-crit"></span>
                  Detected Threat Signals (${signals.length})
                </div>
                <div class="space-y-2">
                  ${signals
                    .map(
                      (sig) => `
                    <div class="p-2.5 rounded-lg bg-panel2/60 border border-line space-y-1.5">
                      <div class="flex items-center gap-2 flex-wrap">
                        ${patternChip(sig.pattern)}
                        ${(sig.mitre || []).map((m) => mitreChip(m)).join(' ')}
                        <span class="text-[10px] font-mono text-muted ml-auto">Severity: ${(sig.severity * 100).toFixed(0)}%</span>
                      </div>
                      <p class="text-xs text-muted leading-relaxed font-sans">${esc(sig.reason)}</p>
                    </div>
                  `
                    )
                    .join('')}
                </div>
              </div>
            `
            : '';

        const locationText = ev.city ? `${ev.city}, ${ev.country}` : ev.region || ev.country || '—';

        return `
          <div
            id="event-step-${idx}"
            data-step="${idx}"
            class="timeline-event-wrapper relative pl-12 transition-all duration-300 ${idx > 0 ? 'opacity-30' : 'opacity-100'}"
          >
            <!-- Step Node on the Line -->
            <div
              class="absolute left-2.5 top-4 w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-mono font-bold transition-all duration-300 z-10 ${
                signals.length > 0
                  ? 'bg-crit/20 border-2 border-crit text-crit'
                  : 'bg-panel border border-line text-muted'
              }"
            >
              ${idx + 1}
            </div>

            <!-- Event Card Body -->
            <div
              id="event-card-${idx}"
              class="bg-panel border border-line rounded-xl p-4 shadow-sm transition-all duration-300 ${
                idx === 0 ? 'ring-2 ring-brand bg-panel2/60 shadow-lg' : ''
              }"
            >
              <!-- Card Header -->
              <div class="flex items-center justify-between gap-3 flex-wrap mb-2">
                <div class="flex items-center gap-2">
                  ${sourceBadge}
                  ${outcomeBadge}
                  <span class="text-xs font-mono text-muted">•</span>
                  <span class="text-xs font-mono font-semibold text-ink">${esc(ev.identity_id || '')}</span>
                </div>

                <div class="flex items-center gap-3 text-xs font-mono text-muted">
                  <span>${fmtTime(ev.timestamp)}</span>
                  <span class="text-[11px] text-muted/60 font-mono">#${esc(ev.event_id || '')}</span>
                </div>
              </div>

              <!-- Action & Target Resource -->
              <div class="space-y-1">
                <div class="font-mono text-sm font-semibold text-ink break-all">
                  ${esc(ev.action || 'unknown.action')}
                </div>
                ${
                  ev.resource
                    ? `
                  <div class="text-xs font-mono text-brand2 flex items-center gap-1.5 break-all">
                    <span class="text-muted">Target:</span>
                    <span>${esc(ev.resource)}</span>
                  </div>
                `
                    : ''
                }
              </div>

              <!-- Context Details: IP, Location, Agent -->
              <div class="mt-3 pt-2.5 border-t border-line/40 grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs text-muted">
                <div>
                  <span class="text-muted/60">IP:</span>
                  <span class="font-mono text-ink ml-1">${esc(ev.src_ip || '—')}</span>
                </div>
                <div>
                  <span class="text-muted/60">Location:</span>
                  <span class="text-ink ml-1">${esc(locationText)}</span>
                </div>
                <div>
                  <span class="text-muted/60">Privilege:</span>
                  <span class="font-mono text-ink ml-1">Level ${ev.privilege_level || 1}/5</span>
                </div>
              </div>

              <!-- Threats & Signals -->
              ${signalsHtml}
            </div>
          </div>
        `;
      })
      .join('');

    container.innerHTML = `
      <div class="relative py-2">
        <!-- Connecting Vertical Guide Line -->
        <div class="absolute left-5 top-6 bottom-6 w-0.5 bg-line z-0"></div>
        <div class="space-y-6">
          ${eventsHtml}
        </div>
      </div>
    `;

    // State Update & UI Synchronization
    function updateStep(newIndex, shouldScroll = true) {
      currentStep = Math.max(0, Math.min(totalEvents - 1, newIndex));

      if (slider) slider.value = String(currentStep);
      if (stepCurrentEl) stepCurrentEl.textContent = String(currentStep + 1);

      const curEv = items[currentStep]?.event;
      if (sliderTimeLabel && curEv) {
        sliderTimeLabel.textContent = fmtTime(curEv.timestamp);
      }

      // Update button disabled states
      if (prevBtn) prevBtn.disabled = currentStep === 0;
      if (nextBtn) nextBtn.disabled = currentStep === totalEvents - 1;

      // Update styles for each event card
      for (let i = 0; i < totalEvents; i++) {
        const wrapEl = document.getElementById(`event-step-${i}`);
        const cardEl = document.getElementById(`event-card-${i}`);
        if (!wrapEl || !cardEl) continue;

        if (i > currentStep) {
          // Dimmed: event is in the future relative to scrubber
          wrapEl.classList.remove('opacity-100');
          wrapEl.classList.add('opacity-30');
          cardEl.classList.remove('ring-2', 'ring-brand', 'bg-panel2/60', 'shadow-lg');
        } else if (i === currentStep) {
          // Active highlighted step
          wrapEl.classList.remove('opacity-30');
          wrapEl.classList.add('opacity-100');
          cardEl.classList.add('ring-2', 'ring-brand', 'bg-panel2/60', 'shadow-lg');
        } else {
          // Revealed past step
          wrapEl.classList.remove('opacity-30');
          wrapEl.classList.add('opacity-100');
          cardEl.classList.remove('ring-2', 'ring-brand', 'bg-panel2/60', 'shadow-lg');
        }
      }

      if (shouldScroll) {
        const activeCard = document.getElementById(`event-step-${currentStep}`);
        if (activeCard) {
          activeCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      }
    }

    function stopPlayback() {
      isPlaying = false;
      if (playTimer) {
        clearInterval(playTimer);
        playTimer = null;
      }
      if (playPauseIcon) playPauseIcon.textContent = '▶';
      if (playPauseText) playPauseText.textContent = 'Play';
      if (playPauseBtn) playPauseBtn.classList.replace('bg-warn', 'bg-brand');
    }

    function startPlayback() {
      if (currentStep >= totalEvents - 1) {
        updateStep(0, false);
      }
      isPlaying = true;
      if (playPauseIcon) playPauseIcon.textContent = '⏸';
      if (playPauseText) playPauseText.textContent = 'Pause';
      if (playPauseBtn) playPauseBtn.classList.replace('bg-brand', 'bg-warn');

      const speedMs = Number(speedSelect?.value) || 1000;
      playTimer = setInterval(() => {
        if (currentStep < totalEvents - 1) {
          updateStep(currentStep + 1, true);
        } else {
          stopPlayback();
        }
      }, speedMs);
    }

    // Bind Event Listeners
    if (playPauseBtn) {
      playPauseBtn.onclick = () => {
        if (isPlaying) stopPlayback();
        else startPlayback();
      };
    }

    if (prevBtn) {
      prevBtn.onclick = () => {
        stopPlayback();
        updateStep(currentStep - 1, true);
      };
    }

    if (nextBtn) {
      nextBtn.onclick = () => {
        stopPlayback();
        updateStep(currentStep + 1, true);
      };
    }

    if (slider) {
      slider.oninput = () => {
        stopPlayback();
        updateStep(Number(slider.value), true);
      };
    }

    if (jumpFirstBtn) {
      jumpFirstBtn.onclick = () => {
        stopPlayback();
        updateStep(0, true);
      };
    }

    if (speedSelect) {
      speedSelect.onchange = () => {
        if (isPlaying) {
          stopPlayback();
          startPlayback();
        }
      };
    }

    // Click on individual step to jump directly
    container.querySelectorAll('.timeline-event-wrapper').forEach((el) => {
      el.onclick = () => {
        const stepIdx = Number(el.dataset.step);
        if (!isNaN(stepIdx)) {
          stopPlayback();
          updateStep(stepIdx, false);
        }
      };
    });

    // Keyboard controls for pleasant accessibility
    window.addEventListener('keydown', (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
      if (e.key === 'ArrowRight') {
        stopPlayback();
        updateStep(currentStep + 1, true);
      } else if (e.key === 'ArrowLeft') {
        stopPlayback();
        updateStep(currentStep - 1, true);
      } else if (e.key === ' ' || e.code === 'Space') {
        e.preventDefault();
        if (isPlaying) stopPlayback();
        else startPlayback();
      }
    });

    // Initial sync
    updateStep(0, false);
  } catch (err) {
    if (container) {
      container.innerHTML = errorState(err.message, 'btn-retry-timeline');
      const retryBtn = document.getElementById('btn-retry-timeline');
      if (retryBtn) retryBtn.onclick = () => initTimeline();
    }
  }
}
