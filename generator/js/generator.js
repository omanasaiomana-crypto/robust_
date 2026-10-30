/**
 * IdentityShield v3 - Attack Generator UI Controller & Transmission Engine
 * Controls connection test, scenario executions, tamper tests, and noise generator.
 * Adheres to PRD §25, context.md Section 17 & 19, and Golden Rule 8.
 */

(function (window) {
  'use strict';

  // In-memory runtime state
  const state = {
    targetUrl: 'http://127.0.0.1:8001',
    keyId: 'test-key-1',
    secret: 'test_super_secret_signing_key_32bytes_long!',
    senderId: 'laptop-2-generator',
    totalRequests: 0,
    acceptedRequests: 0,
    rejectedRequests: 0,
    totalEvents: 0,
    latencySum: 0,
    ngrokQuotaLimit: 20000,
    noiseActive: false,
    noiseTimer: null,
    noiseCountdownTimer: null,
    nextNoiseSeconds: 0,
    activeStepper: null
  };

  // Safe DOM utilities
  function escHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function $(id) {
    return document.getElementById(id);
  }

  // ---------------------------------------------------------------------------
  // INITIALIZATION
  // ---------------------------------------------------------------------------

  function init() {
    bindInputs();
    renderScenarios();
    renderTamperTests();
    bindNoiseControls();
    updateMetricsUI();

    // Auto-test connection on load
    testConnection();
  }

  function bindInputs() {
    const urlInput = $('targetUrl');
    const keyInput = $('keyId');
    const secretInput = $('secretKey');
    const senderInput = $('senderId');
    const testBtn = $('testConnBtn');
    const togglePwdBtn = $('togglePwdBtn');

    if (urlInput) {
      urlInput.value = state.targetUrl;
      urlInput.addEventListener('input', e => { state.targetUrl = e.target.value.trim().replace(/\/+$/, ''); });
    }
    if (keyInput) {
      keyInput.value = state.keyId;
      keyInput.addEventListener('input', e => { state.keyId = e.target.value.trim(); });
    }
    if (secretInput) {
      secretInput.value = state.secret;
      secretInput.addEventListener('input', e => { state.secret = e.target.value; });
    }
    if (senderInput) {
      senderInput.value = state.senderId;
      senderInput.addEventListener('input', e => { state.senderId = e.target.value.trim(); });
    }
    if (testBtn) {
      testBtn.addEventListener('click', testConnection);
    }
    if (togglePwdBtn && secretInput) {
      togglePwdBtn.addEventListener('click', () => {
        secretInput.type = secretInput.type === 'password' ? 'text' : 'password';
      });
    }

    const clearLogBtn = $('clearLogBtn');
    if (clearLogBtn) {
      clearLogBtn.addEventListener('click', () => {
        $('logTableBody').innerHTML = '';
      });
    }

    // Modal close
    const modalClose = $('modalClose');
    const modalOverlay = $('modalOverlay');
    if (modalClose && modalOverlay) {
      modalClose.addEventListener('click', () => modalOverlay.classList.remove('active'));
      modalOverlay.addEventListener('click', e => {
        if (e.target === modalOverlay) modalOverlay.classList.remove('active');
      });
    }
  }

  // ---------------------------------------------------------------------------
  // CONNECTION TEST (GET /ingest/v1/health)
  // ---------------------------------------------------------------------------

  async function testConnection() {
    const connPill = $('connStatusPill');
    const connText = $('connStatusText');
    const testBtn = $('testConnBtn');

    if (connText) connText.textContent = 'Testing...';
    if (testBtn) testBtn.disabled = true;

    const startTime = performance.now();
    try {
      const resp = await fetch(`${state.targetUrl}/ingest/v1/health`, {
        method: 'GET',
        headers: {
          'ngrok-skip-browser-warning': 'true'
        }
      });
      const latency = Math.round(performance.now() - startTime);

      if (resp.ok) {
        const data = await resp.json();
        if (connPill) connPill.className = 'conn-pill connected';
        if (connText) connText.textContent = `Online (${latency}ms)`;
        addLogEntry({
          scenario: 'SYS:HEALTH',
          source: 'ingest',
          eventCount: 0,
          status: resp.status,
          expectedStatus: 200,
          latency: latency,
          response: data
        });
      } else {
        throw new Error(`HTTP ${resp.status}`);
      }
    } catch (err) {
      if (connPill) connPill.className = 'conn-pill';
      if (connText) connText.textContent = 'Disconnected';
      addLogEntry({
        scenario: 'SYS:HEALTH',
        source: 'ingest',
        eventCount: 0,
        status: 0,
        expectedStatus: 200,
        latency: Math.round(performance.now() - startTime),
        response: { error: err.message || 'Connection failed' }
      });
    } finally {
      if (testBtn) testBtn.disabled = false;
    }
  }

  // ---------------------------------------------------------------------------
  // SCENARIO RENDERING & EXECUTION
  // ---------------------------------------------------------------------------

  function renderScenarios() {
    const grid = $('scenariosGrid');
    if (!grid || !window.ShieldScenarios) return;

    grid.innerHTML = '';
    const scenarios = window.ShieldScenarios.SCENARIOS;

    Object.keys(scenarios).forEach(key => {
      const sc = scenarios[key];
      const card = document.createElement('div');
      card.className = `scenario-card ${sc.category === 'hero' ? 'hero' : ''}`;

      let badgeClass = 'card-badge';
      if (sc.category === 'hero') badgeClass += ' hero-badge';
      if (sc.category === 'baseline') badgeClass += ' base-badge';

      card.innerHTML = `
        <div>
          <div class="card-top">
            <span class="${badgeClass}">${escHtml(sc.id)}</span>
            <span style="font-size: 0.7rem; color: var(--muted);">${escHtml(sc.category.toUpperCase())}</span>
          </div>
          <div class="card-title">${escHtml(sc.title)}</div>
          <div class="card-desc">${escHtml(sc.description)}</div>
          <div class="expected-badge">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            ${escHtml(sc.expectedOutcome)}
          </div>
        </div>
        <div class="card-actions">
          <button class="btn btn-primary btn-sm" id="btn-send-${escHtml(sc.id)}">Send All</button>
          <button class="btn btn-secondary btn-sm" id="btn-step-${escHtml(sc.id)}">Step-by-Step</button>
          <button class="btn btn-secondary btn-sm" id="btn-inspect-${escHtml(sc.id)}">Inspect</button>
        </div>
      `;

      grid.appendChild(card);

      // Event listeners
      card.querySelector(`#btn-send-${sc.id}`).addEventListener('click', () => executeScenario(sc.id));
      card.querySelector(`#btn-step-${sc.id}`).addEventListener('click', () => openStepper(sc.id));
      card.querySelector(`#btn-inspect-${sc.id}`).addEventListener('click', () => inspectScenarioPayload(sc.id));
    });
  }

  async function executeScenario(scenarioId) {
    const sc = window.ShieldScenarios.SCENARIOS[scenarioId];
    if (!sc) return;

    const batches = sc.buildBatches();
    // Update sender_id in each batch
    batches.forEach(b => { b.sender_id = state.senderId; });

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      await sendIngestBatch(batch, {
        scenarioId: sc.id,
        expectedStatus: 202
      });

      // 150 ms delay between sequential batches per PRD §25
      if (i < batches.length - 1) {
        await new Promise(r => setTimeout(r, 150));
      }
    }
  }

  function inspectScenarioPayload(scenarioId) {
    const sc = window.ShieldScenarios.SCENARIOS[scenarioId];
    if (!sc) return;
    const batches = sc.buildBatches();
    showModal(`Inspect Payload: ${sc.id} — ${sc.title}`, JSON.stringify(batches, null, 2));
  }

  // ---------------------------------------------------------------------------
  // STEPPER MODAL (STEP-BY-STEP TRANSMISSION)
  // ---------------------------------------------------------------------------

  function openStepper(scenarioId) {
    const sc = window.ShieldScenarios.SCENARIOS[scenarioId];
    if (!sc) return;
    const batches = sc.buildBatches();
    batches.forEach(b => { b.sender_id = state.senderId; });

    state.activeStepper = {
      scenarioId: sc.id,
      title: sc.title,
      batches: batches,
      currentStep: 0
    };

    renderStepperModal();
  }

  function renderStepperModal() {
    const st = state.activeStepper;
    if (!st) return;

    const currentBatch = st.batches[st.currentStep];
    const isLast = st.currentStep === st.batches.length - 1;

    const content = `
// Step ${st.currentStep + 1} of ${st.batches.length}: [${currentBatch.source.toUpperCase()}] Batch (${currentBatch.events.length} events)
${JSON.stringify(currentBatch, null, 2)}
    `;

    showModal(
      `Step-by-Step Execution: ${st.scenarioId} (${st.currentStep + 1}/${st.batches.length})`,
      content,
      `
      <button class="btn btn-secondary btn-sm" id="stepperCancelBtn">Cancel</button>
      <button class="btn btn-primary btn-sm" id="stepperSendStepBtn">
        ${isLast ? 'Send Final Step' : 'Send Step & Next →'}
      </button>
      `
    );

    $('stepperCancelBtn').addEventListener('click', () => {
      $('modalOverlay').classList.remove('active');
      state.activeStepper = null;
    });

    $('stepperSendStepBtn').addEventListener('click', async () => {
      const sendBtn = $('stepperSendStepBtn');
      sendBtn.disabled = true;
      sendBtn.textContent = 'Sending...';

      await sendIngestBatch(currentBatch, {
        scenarioId: `${st.scenarioId} (Step ${st.currentStep + 1})`,
        expectedStatus: 202
      });

      if (isLast) {
        $('modalOverlay').classList.remove('active');
        state.activeStepper = null;
      } else {
        st.currentStep++;
        renderStepperModal();
      }
    });
  }

  // ---------------------------------------------------------------------------
  // TAMPER TESTS RENDERING & RUNNER (T1–T5)
  // ---------------------------------------------------------------------------

  function renderTamperTests() {
    const grid = $('tamperGrid');
    if (!grid || !window.ShieldScenarios) return;

    grid.innerHTML = '';
    const tests = window.ShieldScenarios.TAMPER_TESTS;

    Object.keys(tests).forEach(key => {
      const t = tests[key];
      const card = document.createElement('div');
      card.className = 'tamper-card';

      card.innerHTML = `
        <div>
          <div class="tamper-header">
            <span class="tamper-badge">${escHtml(t.id)}</span>
            <span class="tamper-result-pill" id="tamper-pill-${escHtml(t.id)}"></span>
          </div>
          <div class="tamper-title">${escHtml(t.title)}</div>
          <div class="tamper-desc">${escHtml(t.description)}</div>
          <div class="tamper-expect">Expected HTTP: ${escHtml(t.expectedStatus)}</div>
        </div>
        <button class="btn btn-crit btn-sm" id="btn-tamper-${escHtml(t.id)}">Run Test</button>
      `;

      grid.appendChild(card);
      card.querySelector(`#btn-tamper-${t.id}`).addEventListener('click', () => runTamperTest(t.id));
    });

    const runAllBtn = $('runAllTamperBtn');
    if (runAllBtn) {
      runAllBtn.addEventListener('click', runAllTamperTests);
    }
  }

  async function runTamperTest(testId) {
    const t = window.ShieldScenarios.TAMPER_TESTS[testId];
    if (!t) return;

    const pill = $(`tamper-pill-${t.id}`);
    if (pill) {
      pill.style.display = 'inline-block';
      pill.className = 'tamper-result-pill';
      pill.textContent = 'Running...';
    }

    let batch = {
      source: "okta",
      sender_id: state.senderId,
      batch_id: "batch-tamper-" + testId.toLowerCase(),
      events: [
        window.ShieldScenarios.makeOktaEvent({
          actorEmail: "tamper-test@corp.example"
        })
      ]
    };

    let rawBody = JSON.stringify(batch);
    let options = Object.assign({}, t.options);

    // T5: Oversized body (create > 1.0 MB string)
    if (t.isOversized) {
      const hugePadding = "X".repeat(1.2 * 1024 * 1024);
      batch.events[0].client.userAgent.rawUserAgent = hugePadding;
      rawBody = JSON.stringify(batch);
    }

    // T4: Replay test
    if (t.isReplay) {
      // 1. Send first request normally
      const firstResult = await sendIngestBatch(batch, {
        scenarioId: `${t.id}: Initial Valid Send`,
        expectedStatus: 202
      });

      // 2. Immediately send exact same nonce & signature
      const signed = await window.ShieldSign.signRequest(state.keyId, state.secret, rawBody);
      const replayResult = await sendRawIngest(rawBody, signed.headers, {
        scenarioId: `${t.id}: Replay Nonce Send`,
        expectedStatus: 401
      });

      const passed = replayResult.status === 401;
      updateTamperPill(t.id, passed, replayResult.status);
      return;
    }

    // Standard Tamper Tests (T1, T2, T3, T5)
    const signed = await window.ShieldSign.signRequest(state.keyId, state.secret, rawBody, options);
    const result = await sendRawIngest(rawBody, signed.headers, {
      scenarioId: `${t.id}: ${t.title}`,
      expectedStatus: t.expectedStatus
    });

    const passed = result.status === t.expectedStatus;
    updateTamperPill(t.id, passed, result.status);
  }

  function updateTamperPill(testId, passed, actualStatus) {
    const pill = $(`tamper-pill-${testId}`);
    if (!pill) return;
    pill.style.display = 'inline-block';
    if (passed) {
      pill.className = 'tamper-result-pill passed';
      pill.textContent = `✓ PASSED (${actualStatus})`;
    } else {
      pill.className = 'tamper-result-pill failed';
      pill.textContent = `✗ FAILED (${actualStatus})`;
    }
  }

  async function runAllTamperTests() {
    const tests = ['T1', 'T2', 'T3', 'T4', 'T5'];
    for (const testId of tests) {
      await runTamperTest(testId);
      await new Promise(r => setTimeout(r, 200));
    }
  }

  // ---------------------------------------------------------------------------
  // BACKGROUND NOISE GENERATOR
  // ---------------------------------------------------------------------------

  function bindNoiseControls() {
    const toggle = $('noiseToggle');
    const rateSlider = $('noiseRateSlider');
    const rateVal = $('noiseRateVal');

    if (rateSlider && rateVal) {
      rateSlider.addEventListener('input', e => {
        rateVal.textContent = `${e.target.value}s`;
      });
    }

    if (toggle) {
      toggle.addEventListener('change', e => {
        if (e.target.checked) {
          startNoise();
        } else {
          stopNoise();
        }
      });
    }
  }

  function startNoise() {
    state.noiseActive = true;
    const rateSlider = $('noiseRateSlider');
    const intervalSeconds = Math.max(3, parseInt(rateSlider ? rateSlider.value : 5, 10));

    state.nextNoiseSeconds = intervalSeconds;
    updateNoiseCountdown();

    state.noiseCountdownTimer = setInterval(() => {
      state.nextNoiseSeconds--;
      updateNoiseCountdown();
      if (state.nextNoiseSeconds <= 0) {
        sendNoiseTick();
        state.nextNoiseSeconds = Math.max(3, parseInt(rateSlider ? rateSlider.value : 5, 10));
      }
    }, 1000);
  }

  function stopNoise() {
    state.noiseActive = false;
    clearInterval(state.noiseCountdownTimer);
    const countdownEl = $('noiseCountdown');
    if (countdownEl) countdownEl.textContent = 'Noise generator inactive';
  }

  function updateNoiseCountdown() {
    const countdownEl = $('noiseCountdown');
    if (countdownEl) {
      countdownEl.textContent = `Next noise batch in ${state.nextNoiseSeconds}s...`;
    }
  }

  async function sendNoiseTick() {
    if (!state.noiseActive) return;
    const batch = window.ShieldScenarios.buildNoiseBatch(10);
    batch.sender_id = `${state.senderId}-noise`;
    await sendIngestBatch(batch, {
      scenarioId: 'NOISE (Benign)',
      expectedStatus: 202
    });
  }

  // ---------------------------------------------------------------------------
  // TRANSMISSION ENGINE & LOGGING
  // ---------------------------------------------------------------------------

  async function sendIngestBatch(batch, meta = {}) {
    const rawBody = JSON.stringify(batch);
    const signed = await window.ShieldSign.signRequest(state.keyId, state.secret, rawBody);
    return sendRawIngest(rawBody, signed.headers, meta, batch);
  }

  async function sendRawIngest(rawBody, headers, meta = {}, batch = null) {
    const startTime = performance.now();
    state.totalRequests++;

    let status = 0;
    let respData = null;

    try {
      const resp = await fetch(`${state.targetUrl}/ingest/v1/events`, {
        method: 'POST',
        headers: headers,
        body: rawBody
      });

      status = resp.status;
      try {
        respData = await resp.json();
      } catch {
        respData = { statusText: resp.statusText };
      }

      if (status === 202) {
        state.acceptedRequests++;
        if (respData && respData.accepted_count) {
          state.totalEvents += respData.accepted_count;
        } else if (batch && batch.events) {
          state.totalEvents += batch.events.length;
        }
      } else {
        state.rejectedRequests++;
      }
    } catch (err) {
      status = 0;
      respData = { error: err.message || 'Network / CORS Error' };
      state.rejectedRequests++;
    }

    const latency = Math.round(performance.now() - startTime);
    state.latencySum += latency;

    updateMetricsUI();

    addLogEntry({
      scenario: meta.scenarioId || 'Batch',
      source: batch ? batch.source : 'raw',
      eventCount: batch && batch.events ? batch.events.length : 1,
      status: status,
      expectedStatus: meta.expectedStatus || 202,
      latency: latency,
      response: respData
    });

    return { status, data: respData, latency };
  }

  function addLogEntry(entry) {
    const tbody = $('logTableBody');
    if (!tbody) return;

    const tr = document.createElement('tr');
    const isOk = entry.status === entry.expectedStatus;
    const timeStr = new Date().toLocaleTimeString();

    let statusBadgeClass = 'status-pill ';
    if (entry.status === 202 || entry.status === 200) {
      statusBadgeClass += 'status-202';
    } else {
      statusBadgeClass += 'status-401';
    }

    const respJsonStr = JSON.stringify(entry.response, null, 2);

    tr.innerHTML = `
      <td style="color: var(--muted);">${escHtml(timeStr)}</td>
      <td style="color: var(--text-bright); font-weight: 600;">${escHtml(entry.scenario)}</td>
      <td><span style="color: var(--cyan);">${escHtml(entry.source)}</span></td>
      <td>${escHtml(entry.eventCount)}</td>
      <td>
        <span class="${statusBadgeClass}">${escHtml(entry.status || 'ERR')}</span>
        ${isOk ? '<span style="color: var(--ok); margin-left: 4px;">✓</span>' : '<span style="color: var(--crit); margin-left: 4px;">✗</span>'}
      </td>
      <td>${escHtml(entry.latency)} ms</td>
      <td style="color: var(--muted); font-size: 0.72rem;">${escHtml(entry.response && entry.response.received_at ? entry.response.received_at : '-')}</td>
      <td>
        <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 0.7rem;" data-resp="${escHtml(respJsonStr)}">View</button>
      </td>
    `;

    tr.querySelector('button').addEventListener('click', e => {
      showModal(`Response Inspector: ${entry.scenario}`, e.target.getAttribute('data-resp'));
    });

    if (tbody.firstChild) {
      tbody.insertBefore(tr, tbody.firstChild);
    } else {
      tbody.appendChild(tr);
    }

    // Limit log rows to 100
    while (tbody.children.length > 100) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  function updateMetricsUI() {
    const totalEl = $('metricTotalReqs');
    const acceptedEl = $('metricAccepted');
    const rejectedEl = $('metricRejected');
    const eventsEl = $('metricTotalEvents');
    const avgLatEl = $('metricAvgLatency');
    const quotaFill = $('quotaFill');
    const quotaText = $('quotaText');

    if (totalEl) totalEl.textContent = state.totalRequests;
    if (acceptedEl) acceptedEl.textContent = state.acceptedRequests;
    if (rejectedEl) rejectedEl.textContent = state.rejectedRequests;
    if (eventsEl) eventsEl.textContent = state.totalEvents;

    const avg = state.totalRequests > 0 ? Math.round(state.latencySum / state.totalRequests) : 0;
    if (avgLatEl) avgLatEl.textContent = `${avg} ms`;

    // Quota
    const pct = Math.min(100, (state.totalRequests / state.ngrokQuotaLimit) * 100).toFixed(1);
    if (quotaFill) quotaFill.style.width = `${Math.max(1, pct)}%`;
    if (quotaText) quotaText.textContent = `${state.totalRequests} / ${state.ngrokQuotaLimit.toLocaleString()} monthly`;
  }

  function showModal(title, content, footerHtml = '') {
    const modalTitle = $('modalTitle');
    const modalBody = $('modalBody');
    const modalFooter = $('modalFooter');
    const modalOverlay = $('modalOverlay');

    if (modalTitle) modalTitle.textContent = title;
    if (modalBody) modalBody.textContent = content;
    if (modalFooter) modalFooter.innerHTML = footerHtml;

    if (modalOverlay) modalOverlay.classList.add('active');
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})(window);
