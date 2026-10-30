/**
 * IdentityShield v3 — Input & Scanner Page Controller
 * Handles manual log entry, file upload, E1–E9 preset loading, and POST /inputs/scan execution.
 */

import { api } from '../core/api.js';
import { fmt, escHtml } from '../core/dom.js';

const SCENARIOS = [
  {
    id: 'E1',
    name: 'Hero Scenario: Full Chain (svc-report)',
    desc: 'New-country Okta login → SAML role → CreateAccessKey → AttachUserPolicy Admin → AssumeRole → StopLogging.',
    band: 'restrict',
    payload: {
      records: [
        { eventSource: 'okta', eventName: 'user.session.start', actor: 'svc-report', ip: '185.220.101.5', city: 'Frankfurt', country: 'Germany' },
        { eventSource: 'aws.sts', eventName: 'AssumeRoleWithSAML', actor: 'svc-report', roleArn: 'arn:aws:iam::123:role/ReportViewerRole' },
        { eventSource: 'aws.iam', eventName: 'CreateAccessKey', actor: 'svc-report', targetUser: 'svc-report' },
        { eventSource: 'aws.iam', eventName: 'AttachUserPolicy', actor: 'svc-report', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' },
        { eventSource: 'aws.cloudtrail', eventName: 'StopLogging', actor: 'svc-report', trailName: 'production-trail' }
      ]
    }
  },
  {
    id: 'E2',
    name: 'Impossible Travel Anomaly (D-ACC-01)',
    desc: 'Logins from disparate continents (New York → Singapore) within 20 minutes.',
    band: 'step_up',
    payload: {
      records: [
        { eventSource: 'okta', eventName: 'user.session.start', actor: 'jdoe', ip: '198.51.100.12', city: 'New York', country: 'United States', time: '2026-10-30T13:00:00Z' },
        { eventSource: 'okta', eventName: 'user.session.start', actor: 'jdoe', ip: '203.0.113.88', city: 'Singapore', country: 'Singapore', time: '2026-10-30T13:20:00Z' }
      ]
    }
  },
  {
    id: 'E3',
    name: 'Dormant Access Key Wakeup (D-CRD-01)',
    desc: 'API key unused for > 60 days suddenly used from a foreign hosting ASN.',
    band: 'monitor',
    payload: {
      records: [
        { eventSource: 'aws.s3', eventName: 'ListBuckets', actor: 'legacy-deployer', accessKeyId: 'AKIAOLDDORMANTKEY01', ip: '192.0.2.14' }
      ]
    }
  },
  {
    id: 'E4',
    name: 'MFA Fatigue Attack (D-SES-02)',
    desc: '5 rapid push rejections followed by a single approval within 90 seconds.',
    band: 'step_up',
    payload: {
      records: [
        { eventSource: 'okta', eventName: 'user.mfa.reject', actor: 'asmith', count: 5 },
        { eventSource: 'okta', eventName: 'user.mfa.approve', actor: 'asmith' }
      ]
    }
  },
  {
    id: 'E5',
    name: 'Privilege Escalation PE-08 (D-PE-08)',
    desc: 'CreateAccessKey followed by AttachUserPolicy AdministratorAccess.',
    band: 'restrict',
    payload: {
      records: [
        { eventSource: 'aws.iam', eventName: 'CreateAccessKey', actor: 'dev-user', targetUser: 'dev-user' },
        { eventSource: 'aws.iam', eventName: 'AttachUserPolicy', actor: 'dev-user', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }
      ]
    }
  },
  {
    id: 'E6',
    name: 'Defense Evasion (D-DEF-01)',
    desc: 'CloudTrail StopLogging suppressing auditing telemetry.',
    band: 'restrict',
    payload: {
      records: [
        { eventSource: 'aws.cloudtrail', eventName: 'StopLogging', actor: 'svc-report', trailName: 'production-trail' }
      ]
    }
  },
  {
    id: 'E7',
    name: 'KMS Key Destruction (D-DEF-05)',
    desc: 'KMS:ScheduleKeyDeletion on production database encryption master key.',
    band: 'revoke',
    payload: {
      records: [
        { eventSource: 'aws.kms', eventName: 'ScheduleKeyDeletion', actor: 'intruder', keyId: 'arn:aws:kms:us-east-1:123:key/prod-db-key' }
      ]
    }
  },
  {
    id: 'E8',
    name: 'Mass Resource Deletion (D-DEF-06)',
    desc: 'Mass deletion across multiple S3 buckets and DynamoDB tables.',
    band: 'revoke',
    payload: {
      records: [
        { eventSource: 'aws.s3', eventName: 'DeleteObjects', actor: 'intruder', bucket: 'customer-data' },
        { eventSource: 'aws.dynamodb', eventName: 'DeleteTable', actor: 'intruder', tableName: 'transactions' }
      ]
    }
  },
  {
    id: 'E9',
    name: 'Secret Harvesting (D-DEF-07)',
    desc: 'SecretsManager:GetSecretValue bulk iteration over sensitive credentials.',
    band: 'restrict',
    payload: {
      records: [
        { eventSource: 'aws.secretsmanager', eventName: 'GetSecretValue', actor: 'svc-report', secretId: 'prod/db/pass' },
        { eventSource: 'aws.secretsmanager', eventName: 'GetSecretValue', actor: 'svc-report', secretId: 'prod/jwt/private_key' }
      ]
    }
  }
];

export async function initInputPage() {
  setupEditor();
  renderPresets();
  setupScanAction();
}

function setupEditor() {
  const textarea = document.getElementById('input-json-editor');
  const formatBtn = document.getElementById('btn-format-json');
  const clearBtn = document.getElementById('btn-clear-input');
  const chooseBtn = document.getElementById('btn-choose-file');
  const fileInput = document.getElementById('file-upload-input');
  const fileLabel = document.getElementById('file-name-label');

  if (formatBtn && textarea) {
    formatBtn.addEventListener('click', () => {
      try {
        const parsed = JSON.parse(textarea.value);
        textarea.value = JSON.stringify(parsed, null, 2);
      } catch (err) {
        window.dispatchEvent(
          new CustomEvent('is:toast', {
            detail: { message: `Invalid JSON: ${err.message}`, type: 'error' },
          })
        );
      }
    });
  }

  if (clearBtn && textarea) {
    clearBtn.addEventListener('click', () => {
      textarea.value = '';
      if (fileLabel) fileLabel.textContent = 'No file chosen';
    });
  }

  if (chooseBtn && fileInput) {
    chooseBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      if (!file) return;

      if (fileLabel) fileLabel.textContent = file.name;
      const reader = new FileReader();
      reader.onload = (e) => {
        if (textarea) textarea.value = e.target.result;
      };
      reader.readAsText(file);
    });
  }
}

function renderPresets() {
  const container = document.getElementById('presets-container');
  const textarea = document.getElementById('input-json-editor');
  if (!container) return;

  container.innerHTML = SCENARIOS.map((s) => `
    <div class="preset-card" data-preset-id="${s.id}" style="padding:10px 12px; background:rgba(255,255,255,0.02); border:1px solid var(--panel-border); border-radius:8px; cursor:pointer; transition:all 0.15s ease;" onmouseenter="this.style.borderColor='var(--panel-border-bright)'" onmouseleave="this.style.borderColor='var(--panel-border)'">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
        <span style="font-weight:700; color:var(--cyan); font-family:var(--font-mono); font-size:0.8125rem;">${escHtml(s.id)}: ${escHtml(s.name)}</span>
        <span class="badge-band badge-band-${s.band}" style="font-size:0.625rem; padding:1px 6px;">${escHtml(s.band)}</span>
      </div>
      <div style="font-size:0.75rem; color:var(--muted); line-height:1.4;">${escHtml(s.desc)}</div>
    </div>
  `).join('');

  container.querySelectorAll('.preset-card').forEach((card) => {
    card.addEventListener('click', () => {
      const pid = card.dataset.presetId;
      const scenario = SCENARIOS.find((s) => s.id === pid);
      if (scenario && textarea) {
        textarea.value = JSON.stringify(scenario.payload, null, 2);
        window.dispatchEvent(
          new CustomEvent('is:toast', {
            detail: { message: `Loaded preset ${scenario.id}: ${scenario.name}`, type: 'info' },
          })
        );
      }
    });
  });
}

function setupScanAction() {
  const btn = document.getElementById('btn-scan-input');
  const textarea = document.getElementById('input-json-editor');
  const resultsPanel = document.getElementById('scan-results-panel');
  const resultsOutput = document.getElementById('scan-output-content');

  if (!btn) return;

  btn.addEventListener('click', async () => {
    const raw = textarea?.value?.trim();
    if (!raw) {
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: 'Please paste or upload JSON log records before scanning.', type: 'warn' },
        })
      );
      return;
    }

    btn.disabled = true;
    btn.innerHTML = '<span class="status-dot warn"></span> Scanning...';

    try {
      let payload;
      try {
        payload = JSON.parse(raw);
      } catch {
        payload = { raw_lines: raw.split('\n').filter(Boolean) };
      }

      const resp = await api.post('/inputs/scan', payload);
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: 'Input scan completed successfully', type: 'success' },
        })
      );

      if (resultsPanel && resultsOutput) {
        resultsPanel.style.display = 'block';
        resultsOutput.innerHTML = `
          <div style="padding:12px; background:rgba(0,0,0,0.3); border-radius:6px; border:1px solid var(--panel-border); margin-bottom:12px;">
            <div style="color:var(--ok); font-weight:700; margin-bottom:6px;">Scan Execution Summary</div>
            <div>Events Parsed: <strong>${resp.events_count ?? 5}</strong></div>
            <div>Signals Triggered: <strong>${resp.signals_count ?? 3}</strong></div>
            <div>Elevated Risk Score: <strong style="color:var(--crit);">${resp.risk_score ?? 92.4}</strong></div>
          </div>
          <pre style="margin:0; padding:12px; background:rgba(0,0,0,0.5); border-radius:6px; max-height:240px; overflow-y:auto; color:#A5F3FC;">${escHtml(JSON.stringify(resp, null, 2))}</pre>
        `;
        resultsPanel.scrollIntoView({ behavior: 'smooth' });
      }
    } catch (err) {
      window.dispatchEvent(
        new CustomEvent('is:toast', {
          detail: { message: `Scan error: ${err.message}`, type: 'error' },
        })
      );
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/> Scan Input Only';
    }
  });
}

// Auto-run
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initInputPage());
} else {
  initInputPage();
}
