import { initButtons } from '../fx/buttons.js';
/**
 * IdentityShield v3 — Navigation Shell, Topbar, Toasts, & Command Palette
 * Context.md Section 18 / PRD §18: Dual Theme (Cream Light & Dark Command Center)
 */

// Anti-flash initial theme apply
try {
  const _savedTheme = localStorage.getItem('identityshield_theme') || 'light';
  document.documentElement.setAttribute('data-theme', _savedTheme);
} catch (e) {}

import { api } from './api.js';
import { sse } from './sse.js';
import { escHtml } from './dom.js';

const NAV_ITEMS = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    href: '/v3/index.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>`,
  },
  {
    id: 'live',
    label: 'Live Stream',
    href: '/v3/live.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
  },
  {
    id: 'cases',
    label: 'Threat Cases',
    href: '/v3/cases.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><circle cx="12" cy="11" r="3"/></svg>`,
  },
  {
    id: 'graph',
    label: 'Graph 3D',
    href: '/v3/graph.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`,
  },
  {
    id: 'globe',
    label: 'Login Globe',
    href: '/v3/globe.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
  },
  {
    id: 'agents',
    label: '15 Agents',
    href: '/v3/agents.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="9" cy="9" r="2"/><circle cx="15" cy="15" r="2"/><path d="M9 15h.01"/><path d="M15 9h.01"/></svg>`,
  },
  {
    id: 'analytics',
    label: 'Analytics',
    href: '/v3/analytics.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>`,
  },
  {
    id: 'performance',
    label: 'Performance',
    href: '/v3/performance.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>`,
  },
  {
    id: 'input',
    label: 'Ingest & Scan',
    href: '/v3/input.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  },
  {
    id: 'audit',
    label: 'Audit Trail',
    href: '/v3/audit.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`,
  },
  {
    id: 'settings',
    label: 'Settings',
    href: '/v3/settings.html',
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  },
];

export class Shell {
  constructor() {
    this.isCollapsed = this._loadCollapsed();
    this.currentPath = window.location.pathname;
    this.toastContainer = null;
    this.clockEl = null;
    this.epsEl = null;
    this.ingestDot = null;
    this.ingestText = null;
    this.statusPill = null;
    this.cmdModal = null;
    this.themeBtn = null;
  }

  _loadCollapsed() {
    try {
      return localStorage.getItem('identityshield_v3_sidebar_collapsed') === '1';
    } catch {
      return false;
    }
  }

  _saveCollapsed(collapsed) {
    try {
      localStorage.setItem('identityshield_v3_sidebar_collapsed', collapsed ? '1' : '0');
    } catch (e) {
      console.warn('Failed to persist sidebar state', e);
    }
  }

  init() {
    this._initTheme();
    this._renderToastContainer();
    this._renderShell();
    this._setupClock();
    this._setupHealthPoll();
    this._setupSSEMetrics();
    this._setupCommandPalette();
    initButtons(document);
    this._listenToasts();
  }

  _renderToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
    this.toastContainer = container;
  }

  showToast(message, type = 'info', duration = 4000) {
    if (!this.toastContainer) this._renderToastContainer();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    const textSpan = document.createElement('span');
    textSpan.textContent = message;
    toast.appendChild(textSpan);

    this.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-10px) scale(0.95)';
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  _listenToasts() {
    window.addEventListener('is:toast', (e) => {
      if (e.detail) {
        this.showToast(e.detail.message, e.detail.type || 'info');
      }
    });
  }

  _renderShell() {
    const existingShell = document.querySelector('.app-shell');
    if (existingShell) return;

    // Grab current main content if already exists
    const mainContentEl = document.getElementById('main-content');
    const pageContentChildren = mainContentEl ? Array.from(mainContentEl.childNodes) : [];

    const shell = document.createElement('div');
    shell.className = 'app-shell';

    // 1. Sidebar
    const sidebar = document.createElement('aside');
    sidebar.className = `app-sidebar ${this.isCollapsed ? 'collapsed' : ''}`;
    sidebar.id = 'app-sidebar';

    // Sidebar Header / Logo
    const header = document.createElement('div');
    header.className = 'app-sidebar-header';
    header.innerHTML = `
      <a href="/v3/index.html" class="app-sidebar-brand">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#3D6FE0" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <polyline points="9 12 11 14 15 10"/>
        </svg>
        <span>IdentityShield <span style="font-size:0.6875rem; color:#3D6FE0; font-family:var(--font-mono); font-weight:700;">v3</span></span>
      </a>
    `;
    sidebar.appendChild(header);

    // Sidebar Navigation
    const nav = document.createElement('nav');
    nav.className = 'app-sidebar-nav';

    for (const item of NAV_ITEMS) {
      const a = document.createElement('a');
      a.className = 'nav-item';
      a.href = item.href;
      a.title = item.label;

      // Active item detection
      const isCurrent =
        this.currentPath.endsWith(item.href) ||
        (item.href.endsWith('index.html') && (this.currentPath === '/v3/' || this.currentPath === '/v3'));
      if (isCurrent) {
        a.classList.add('active');
      }

      a.innerHTML = `${item.icon} <span class="nav-text">${item.label}</span>`;
      nav.appendChild(a);
    }
    sidebar.appendChild(nav);

    // Sidebar Footer (Collapse Toggle)
    const footer = document.createElement('div');
    footer.className = 'app-sidebar-footer';
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'sidebar-toggle-btn';
    toggleBtn.type = 'button';
    toggleBtn.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
        <line x1="9" y1="3" x2="9" y2="21"/>
      </svg>
      <span>Collapse View</span>
    `;
    toggleBtn.addEventListener('click', () => {
      this.isCollapsed = !this.isCollapsed;
      sidebar.classList.toggle('collapsed', this.isCollapsed);
      this._saveCollapsed(this.isCollapsed);
    });
    footer.appendChild(toggleBtn);
    sidebar.appendChild(footer);

    shell.appendChild(sidebar);

    // 2. Main Area (Topbar + Content)
    const main = document.createElement('div');
    main.className = 'app-main';

    // Topbar
    const topbar = document.createElement('header');
    topbar.className = 'app-topbar';

    // Topbar Left: System Status & Live EPS
    const topbarLeft = document.createElement('div');
    topbarLeft.className = 'topbar-left';

    const statusPill = document.createElement('div');
    statusPill.className = 'status-pill';
    statusPill.innerHTML = `<span class="status-dot ok"></span> <span id="run-status-text">SYSTEM READY</span>`;
    this.statusPill = statusPill;
    topbarLeft.appendChild(statusPill);

    const epsMetric = document.createElement('div');
    epsMetric.className = 'topbar-metric';
    epsMetric.innerHTML = `<span>EPS:</span> <strong id="topbar-eps">0.0</strong>`;
    this.epsEl = epsMetric.querySelector('#topbar-eps');
    topbarLeft.appendChild(epsMetric);

    const ingestStatus = document.createElement('button');
    ingestStatus.type = 'button';
    ingestStatus.className = 'topbar-metric';
    ingestStatus.id = 'topbar-ingest-status-btn';
    ingestStatus.style.cursor = 'pointer';
    ingestStatus.style.background = api.isMock ? 'var(--rose-pastel)' : 'var(--mint-pastel)';
    ingestStatus.style.border = api.isMock ? '1px solid rgba(200, 30, 30, 0.3)' : '1px solid rgba(15, 138, 106, 0.3)';
    ingestStatus.style.color = api.isMock ? 'var(--rose-strong)' : 'var(--mint-strong)';
    ingestStatus.style.borderRadius = '6px';
    ingestStatus.style.padding = '4px 8px';
    ingestStatus.style.display = 'inline-flex';
    ingestStatus.style.alignItems = 'center';
    ingestStatus.style.gap = '6px';
    ingestStatus.innerHTML = `
      <span class="status-dot ${api.isMock ? 'warn' : 'ok'}" id="ingest-status-dot"></span>
      <span style="font-weight:600;">INGEST:</span>
      <strong id="ingest-status-text">${api.isMock ? 'MOCK MODE (Click for LIVE)' : '8001 ACTIVE'}</strong>
    `;
    ingestStatus.addEventListener('click', () => {
      if (api.isMock) {
        api.setMock(false);
        const u = new URL(window.location.href);
        u.searchParams.delete('mock');
        window.location.href = u.toString();
      } else {
        api.setMock(true);
        window.location.reload();
      }
    });
    this.ingestDot = ingestStatus.querySelector('#ingest-status-dot');
    this.ingestText = ingestStatus.querySelector('#ingest-status-text');
    topbarLeft.appendChild(ingestStatus);

    topbar.appendChild(topbarLeft);

    // Topbar Right: Clock & Command Palette Trigger
    const topbarRight = document.createElement('div');
    topbarRight.className = 'topbar-right';

    const cmdBtn = document.createElement('button');
    cmdBtn.className = 'cmd-palette-btn';
    cmdBtn.type = 'button';
    cmdBtn.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <span>Search</span>
      <kbd class="cmd-kbd">Ctrl K</kbd>
    `;
    cmdBtn.addEventListener('click', () => this.openCommandPalette());
    topbarRight.appendChild(cmdBtn);

    // Theme Toggle Button
    this._renderThemeToggle(topbarRight);

    const clock = document.createElement('div');
    clock.className = 'topbar-clock';
    clock.id = 'topbar-clock';
    clock.textContent = '--:--:-- UTC';
    this.clockEl = clock;
    topbarRight.appendChild(clock);

    topbar.appendChild(topbarRight);
    main.appendChild(topbar);

    // Content container
    const content = document.createElement('main');
    content.className = 'app-content';
    content.id = 'app-content';

    // Transfer original page contents
    if (pageContentChildren.length > 0) {
      for (const node of pageContentChildren) {
        content.appendChild(node);
      }
      if (mainContentEl) mainContentEl.remove();
    }
    main.appendChild(content);

    shell.appendChild(main);
    document.body.appendChild(shell);
  }

  _setupClock() {
    const update = () => {
      if (!this.clockEl) return;
      const now = new Date();
      const utcStr = now.toISOString().substring(11, 19) + ' UTC';
      this.clockEl.textContent = utcStr;
    };
    update();
    setInterval(update, 1000);
  }

  _setupHealthPoll() {
    const check = async () => {
      try {
        const data = await api.get('/health');
        if (data && data.status === 'ok') {
          if (this.ingestDot) this.ingestDot.className = api.isMock ? 'status-dot warn' : 'status-dot ok';
          if (this.ingestText) this.ingestText.textContent = api.isMock ? 'MOCK MODE (Click for LIVE)' : '8001 ACTIVE';
        } else {
          if (this.ingestDot) this.ingestDot.className = 'status-dot warn';
          if (this.ingestText) this.ingestText.textContent = 'DEGRADED';
        }
      } catch {
        if (this.ingestDot) this.ingestDot.className = 'status-dot crit';
        if (this.ingestText) this.ingestText.textContent = 'OFFLINE';
      }
    };
    check();
    setInterval(check, 5000);
  }

  _setupSSEMetrics() {
    sse.on('metrics', (data) => {
      if (data && data.eps !== undefined && this.epsEl) {
        this.epsEl.textContent = Number(data.eps).toFixed(1);
      }
    });

    sse.on('trace', (data) => {
      if (data && data.data && data.data.eps && this.epsEl) {
        this.epsEl.textContent = Number(data.data.eps).toFixed(1);
      }
    });
    sse.connect();
  }

  _setupCommandPalette() {
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        this.openCommandPalette();
      }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        this.toggleTheme();
      }
      if (e.key === 'Escape' && this.cmdModal) {
        this.closeCommandPalette();
      }
    });
  }

  openCommandPalette() {
    if (this.cmdModal) return;

    const backdrop = document.createElement('div');
    backdrop.className = 'cmd-palette-backdrop';
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) this.closeCommandPalette();
    });

    const modal = document.createElement('div');
    modal.className = 'cmd-palette-modal';

    const inputWrap = document.createElement('div');
    inputWrap.className = 'cmd-palette-input-wrap';
    inputWrap.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#94A3B8" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <input type="text" class="cmd-palette-input" placeholder="Type a page, command, or Case ID (e.g. E1)..." autofocus />
      <kbd class="cmd-kbd">ESC</kbd>
    `;

    const input = inputWrap.querySelector('input');
    const list = document.createElement('div');
    list.className = 'cmd-palette-list';

    const defaultCommands = [
      ...NAV_ITEMS.map((n) => ({
        label: `Go to ${n.label}`,
        sub: n.href,
        action: () => (window.location.href = n.href),
      })),
      {
        label: 'Hero Case: E1 (svc-report)',
        sub: 'Open active E1 investigation details',
        action: () => (window.location.href = '/v3/cases.html?case_id=case-e1-svcreport'),
      },
      {
        label: 'Toggle Theme (Light / Dark)',
        sub: `Currently ${this.getTheme() === 'dark' ? 'Dark Command Center' : 'Cream Light'} Mode (Ctrl+Shift+D)`,
        action: () => this.toggleTheme(),
      },
      {
        label: 'Toggle Mock Mode (?mock=1)',
        sub: api.isMock ? 'Switch to backend live mode' : 'Switch to standalone mock mode',
        action: () => {
          try {
            if (api.isMock) {
              localStorage.removeItem('identityshield_mock');
            } else {
              localStorage.setItem('identityshield_mock', '1');
            }
            window.location.reload();
          } catch {
            window.location.reload();
          }
        },
      },
      {
        label: 'Set Analyst Token',
        sub: 'Configure X-Analyst-Token in localStorage',
        action: () => {
          const current = api.getAnalystToken();
          const token = prompt('Enter Analyst Token for mutating actions:', current);
          if (token !== null) {
            api.setAnalystToken(token.trim());
            this.showToast('Analyst token updated', 'success');
          }
        },
      },
    ];

    const renderItems = (items) => {
      list.innerHTML = '';
      if (items.length === 0) {
        list.innerHTML = '<div style="padding:16px; text-align:center; color:var(--muted);">No matching commands or cases found.</div>';
        return;
      }

      items.forEach((cmd, idx) => {
        const item = document.createElement('div');
        item.className = `cmd-palette-item ${idx === 0 ? 'selected' : ''}`;
        item.innerHTML = `
          <span>${escHtml(cmd.label)}</span>
          <span style="font-size:0.75rem; color:var(--muted); font-family:var(--font-mono);">${escHtml(cmd.sub)}</span>
        `;
        item.addEventListener('click', () => {
          this.closeCommandPalette();
          cmd.action();
        });
        list.appendChild(item);
      });
    };

    renderItems(defaultCommands);

    input.addEventListener('input', () => {
      const q = input.value.trim().toLowerCase();
      if (!q) {
        renderItems(defaultCommands);
        return;
      }
      const filtered = defaultCommands.filter(
        (c) => c.label.toLowerCase().includes(q) || c.sub.toLowerCase().includes(q)
      );
      renderItems(filtered);
    });

    input.addEventListener('keydown', (e) => {
      const items = Array.from(list.querySelectorAll('.cmd-palette-item'));
      let selectedIdx = items.findIndex((i) => i.classList.contains('selected'));

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (items.length > 0) {
          if (selectedIdx >= 0) items[selectedIdx].classList.remove('selected');
          selectedIdx = (selectedIdx + 1) % items.length;
          items[selectedIdx].classList.add('selected');
          items[selectedIdx].scrollIntoView({ block: 'nearest' });
        }
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (items.length > 0) {
          if (selectedIdx >= 0) items[selectedIdx].classList.remove('selected');
          selectedIdx = (selectedIdx - 1 + items.length) % items.length;
          items[selectedIdx].classList.add('selected');
          items[selectedIdx].scrollIntoView({ block: 'nearest' });
        }
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (selectedIdx >= 0 && items[selectedIdx]) {
          items[selectedIdx].click();
        }
      }
    });

    modal.appendChild(inputWrap);
    modal.appendChild(list);
    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);
    this.cmdModal = backdrop;
    setTimeout(() => input.focus(), 50);
  }

  closeCommandPalette() {
    if (this.cmdModal) {
      this.cmdModal.remove();
      this.cmdModal = null;
    }
  }

  _initTheme() {
    const theme = this.getTheme();
    document.documentElement.setAttribute('data-theme', theme);
  }

  getTheme() {
    try {
      return localStorage.getItem('identityshield_theme') || 'light';
    } catch {
      return 'light';
    }
  }

  setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('identityshield_theme', theme);
    } catch (e) {
      console.warn('Failed to save theme in localStorage', e);
    }
    this._updateThemeBtn(theme);
    window.dispatchEvent(new CustomEvent('is:theme-change', { detail: { theme } }));
    this.showToast(`Switched to ${theme === 'dark' ? 'Dark Command Center' : 'Cream Light'} Mode`, 'info', 2000);
  }

  toggleTheme() {
    const next = this.getTheme() === 'dark' ? 'light' : 'dark';
    this.setTheme(next);
  }

  _renderThemeToggle(container) {
    const btn = document.createElement('button');
    btn.id = 'topbar-theme-toggle';
    btn.className = 'theme-toggle-btn btn-3d btn-ripple';
    btn.type = 'button';
    this.themeBtn = btn;
    this._updateThemeBtn(this.getTheme());

    btn.addEventListener('click', () => {
      this.toggleTheme();
    });

    container.appendChild(btn);
  }

  _updateThemeBtn(theme) {
    if (!this.themeBtn) return;
    const isDark = theme === 'dark';
    this.themeBtn.title = isDark
      ? 'Switch to Cream Light Theme (Ctrl+Shift+D)'
      : 'Switch to Dark Command Center Theme (Ctrl+Shift+D)';
    this.themeBtn.innerHTML = `
      <span class="theme-toggle-icon">
        ${
          isDark
            ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`
            : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`
        }
      </span>
      <span>${isDark ? 'Dark' : 'Light'}</span>
    `;
  }
}

export const shell = new Shell();

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => shell.init());
} else {
  shell.init();
}

export default shell;
