/**
 * Enterprise console sidebar + top bar layout.
 */
import { api, esc, qs } from './api.js';
import { toast } from './ui.js';

export function renderLayout(active, title, subtitle) {
  const app = document.getElementById('app');
  if (!app) return null;

  const isMock = qs('mock') === '1';
  const querySuffix = isMock ? '?mock=1' : '';

  const navItems = [
    {
      id: 'overview',
      label: 'Overview',
      href: `/index.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg>`,
    },
    {
      id: 'scan',
      label: 'Live scan',
      href: `/scan.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>`,
    },
    {
      id: 'agents',
      label: 'Agents',
      href: `/agents.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M3 9h2m-2 6h2m14-6h2m-2 6h2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg>`,
    },
    {
      id: 'input',
      label: 'Input data',
      href: `/input.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>`,
    },
    {
      id: 'alerts',
      label: 'Alerts',
      href: `/alerts.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>`,
    },
    {
      id: 'memory',
      label: '30-Day Memory',
      href: `/memory.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><circle cx="12" cy="12" r="9" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 7v5l3 3"/></svg>`,
    },
    {
      id: 'identities',
      label: 'Identities',
      href: `/identities.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>`,
    },
    {
      id: 'explorer',
      label: 'Attack paths',
      href: `/explorer.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"/></svg>`,
    },
    {
      id: 'analytics',
      label: 'Analytics',
      href: `/analytics.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
    },
    {
      id: 'hygiene',
      label: 'Hygiene',
      href: `/hygiene.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`,
    },
    {
      id: 'audit',
      label: 'Audit Log',
      href: `/audit.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>`,
    },
    {
      id: 'notifications',
      label: 'Notifications',
      href: `/notifications.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>`,
    },
  ];

  app.innerHTML = `
    <div class="min-h-screen bg-bg flex flex-col md:flex-row text-ink">
      <!-- Mobile Backdrop -->
      <div id="mobile-backdrop" class="fixed inset-0 bg-black/60 z-30 hidden md:hidden"></div>

      <!-- Left Sidebar -->
      <aside id="sidebar" class="fixed inset-y-0 left-0 z-40 w-60 bg-panel border-r border-line flex flex-col transform -translate-x-full md:translate-x-0 transition-transform duration-200 ease-in-out md:static md:h-screen md:sticky md:top-0">
        <!-- Logo -->
        <div class="h-16 px-5 border-b border-line flex items-center gap-3 flex-shrink-0">
          <div class="logo-box w-8 h-8 rounded-lg bg-brand/15 border border-brand/30 flex items-center justify-center text-brand transition-all">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div class="text-sm font-bold tracking-tight text-ink">IdentityShield</div>
            <div class="text-[10px] text-muted font-mono tracking-wider uppercase">Zero Trust SOC</div>
          </div>
        </div>

        <!-- Navigation -->
        <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          ${navItems
            .map((item) => {
              const isActive = active === item.id;
              const activeClass = isActive
                ? 'active-nav bg-panel2 text-ink font-semibold border-l-2 border-brand shadow-sm'
                : 'nav-item text-muted hover:bg-panel2/60 hover:text-ink';
              return `
                <a href="${item.href}" class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${activeClass}">
                  ${item.icon}
                  <span>${esc(item.label)}</span>
                </a>
              `;
            })
            .join('')}
        </nav>

        <!-- Download Reports Box in Sidebar -->
        <div class="px-3 py-3 border-t border-line">
          <div class="p-3 rounded-lg bg-panel2/80 border border-line/60">
            <div class="flex items-center gap-2 text-xs font-semibold text-ink">
              <svg class="w-4 h-4 text-brand" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
              </svg>
              <span>Download Report</span>
            </div>
            <p class="text-[11px] text-muted mt-1 leading-snug">Attack summary with agent attribution & heatmaps.</p>
            <div class="mt-2.5 flex flex-col gap-1.5">
              <a href="/api/reports/download/docx" download class="inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-brand/15 hover:bg-brand/25 text-brand border border-brand/30 text-xs font-medium transition-colors">
                <span>📄 Word Report (.docx)</span>
              </a>
              <a href="/api/reports/download/html" download class="inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-cyan-400/15 hover:bg-cyan-400/25 text-cyan-300 border border-cyan-400/30 text-xs font-medium transition-colors">
                <span>🌐 Interactive Report (.html)</span>
              </a>
            </div>
          </div>
        </div>

        <!-- Sidebar Footer & Power Button -->
        <div class="p-3 border-t border-line text-xs flex flex-col gap-2.5">
          <button id="btn-sidebar-theme" class="power-button-sidebar w-full flex items-center justify-between px-3 py-2 rounded-xl border transition-all duration-200 cursor-pointer shadow-sm" title="Power Switch: Light / Dark Mode">
            <div class="flex items-center gap-2.5">
              <span class="power-icon-ring flex items-center justify-center w-6 h-6 rounded-full transition-transform">
                <svg class="w-3.5 h-3.5 power-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path>
                  <line x1="12" y1="2" x2="12" y2="12"></line>
                </svg>
              </span>
              <div class="text-left">
                <div id="side-power-title" class="text-xs font-bold leading-tight">Theme Power</div>
                <div id="side-power-sub" class="text-[10px] leading-tight font-mono text-muted">Click to toggle</div>
              </div>
            </div>
            <span id="side-power-pill" class="text-[10px] font-mono uppercase px-2 py-0.5 rounded-full font-bold"></span>
          </button>
          <div class="flex items-center justify-between text-muted px-0.5">
            <span class="font-mono text-[11px]">Track 2: Zero Trust</span>
            <span class="px-1.5 py-0.5 rounded bg-panel2 text-[10px] font-mono border border-line">v1.0</span>
          </div>
        </div>
      </aside>

      <!-- Main Area -->
      <div class="flex-1 flex flex-col min-w-0">
        <!-- Top Bar -->
        <header class="h-16 px-4 md:px-6 border-b border-line bg-panel/50 backdrop-blur-md sticky top-0 z-20 flex items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <button id="mobile-menu-btn" class="md:hidden p-2 rounded-lg text-muted hover:bg-panel2 focus:outline-none" aria-label="Toggle menu">
              <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <div>
              <h1 class="text-base md:text-lg font-semibold text-ink leading-tight">${esc(title)}</h1>
              ${subtitle ? `<p class="text-xs text-muted leading-tight mt-0.5 hidden sm:block">${esc(subtitle)}</p>` : ''}
            </div>
          </div>

          <!-- Status and Actions -->
          <div class="flex items-center gap-2 md:gap-3 flex-shrink-0">
            <!-- Pipeline Status Pill -->
            <div id="status-pill" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border border-line bg-panel2 text-muted">
              <span class="w-2 h-2 rounded-full bg-muted animate-pulse"></span>
              <span>Loading...</span>
            </div>

            <!-- Data Mode Pill -->
            <div id="mode-pill" class="hidden sm:inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border border-line bg-panel2 text-muted font-mono">
              Mode: ...
            </div>

            <!-- Power Button Theme Toggle -->
            <button id="btn-theme-toggle" aria-label="Toggle Power Theme" title="Power Button - Switch Light / Dark Theme" class="power-button relative inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold border transition-all duration-200 cursor-pointer shadow-sm">
              <span class="power-icon-ring relative flex items-center justify-center w-5 h-5 rounded-full transition-transform">
                <svg class="w-3.5 h-3.5 power-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path>
                  <line x1="12" y1="2" x2="12" y2="12"></line>
                </svg>
              </span>
              <span id="top-power-icon" class="text-sm">☀️</span>
              <span id="top-power-label" class="font-mono tracking-wider text-[11px] uppercase hidden sm:inline font-bold">LIGHT ON</span>
            </button>

            <!-- Download Report Dropdown / Button in Top Bar -->
            <a href="/api/reports/download/docx" download class="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors" title="Download Word Attack Report with Heatmaps">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
              </svg>
              <span>Download (.docx)</span>
            </a>

            <!-- Re-run Pipeline Button -->
            <button id="btn-rerun" aria-label="Re-run detection pipeline" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-brand/10 hover:bg-brand/20 text-brand border border-brand/30 transition-colors">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              <span>Re-run</span>
            </button>
          </div>
        </header>

        <!-- Page Content Container -->
        <main id="page-content" class="flex-1 p-4 md:p-6 max-w-7xl w-full mx-auto space-y-6"></main>
      </div>
    </div>
  `;

  // Apply theme to newly rendered UI elements
  applyTheme(getSavedTheme());

  // Setup theme toggle buttons
  const themeToggle = document.getElementById('btn-theme-toggle');
  if (themeToggle) themeToggle.onclick = toggleTheme;

  const sidebarThemeToggle = document.getElementById('btn-sidebar-theme');
  if (sidebarThemeToggle) sidebarThemeToggle.onclick = toggleTheme;

  // Setup mobile navigation toggle
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('mobile-backdrop');
  const menuBtn = document.getElementById('mobile-menu-btn');

  const toggleSidebar = () => {
    const isClosed = sidebar.classList.contains('-translate-x-full');
    if (isClosed) {
      sidebar.classList.remove('-translate-x-full');
      backdrop.classList.remove('hidden');
    } else {
      sidebar.classList.add('-translate-x-full');
      backdrop.classList.add('hidden');
    }
  };

  if (menuBtn) menuBtn.onclick = toggleSidebar;
  if (backdrop) backdrop.onclick = toggleSidebar;

  // Setup Re-run button
  const rerunBtn = document.getElementById('btn-rerun');
  if (rerunBtn) {
    rerunBtn.onclick = async () => {
      rerunBtn.disabled = true;
      rerunBtn.classList.add('opacity-50');
      try {
        toast('Re-running pipeline...', 'success');
        await api('/pipeline/run', { method: 'POST', body: {} });
        toast('Pipeline execution completed! Refreshing...', 'success');
        setTimeout(() => window.location.reload(), 800);
      } catch (err) {
        toast(`Pipeline run failed: ${err.message}`, 'error');
        rerunBtn.disabled = false;
        rerunBtn.classList.remove('opacity-50');
      }
    };
  }

  // Fetch health to populate status pills
  api('/health')
    .then((health) => {
      const statusPill = document.getElementById('status-pill');
      const modePill = document.getElementById('mode-pill');

      if (statusPill) {
        if (health.pipeline === 'ok' && health.status === 'ok') {
          statusPill.innerHTML = `<span class="w-2 h-2 rounded-full bg-ok"></span><span class="text-ok font-medium">Pipeline OK</span>`;
          statusPill.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border border-ok/30 bg-ok/10';
        } else if (health.status === 'degraded') {
          statusPill.innerHTML = `<span class="w-2 h-2 rounded-full bg-warn"></span><span class="text-warn font-medium">Degraded</span>`;
          statusPill.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border border-warn/30 bg-warn/10';
        } else {
          statusPill.innerHTML = `<span class="w-2 h-2 rounded-full bg-crit"></span><span class="text-crit font-medium">Failed</span>`;
          statusPill.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border border-crit/30 bg-crit/10';
        }
      }

      if (modePill) {
        const modeLabel = health.data_mode === 'official' ? 'Official Data' : 'Sample Data';
        modePill.textContent = modeLabel;
        modePill.className = 'hidden sm:inline-flex items-center px-2.5 py-1 rounded-full text-xs border border-line bg-panel2 text-ink font-mono';
      }
    })
    .catch(() => {
      const statusPill = document.getElementById('status-pill');
      if (statusPill) {
        statusPill.innerHTML = `<span class="w-2 h-2 rounded-full bg-crit"></span><span class="text-crit font-medium">Offline</span>`;
      }
    });

  return document.getElementById('page-content');
}

// --- Theme Handling ---
export function getSavedTheme() {
  try {
    return localStorage.getItem('identityshield_theme') || 'dark';
  } catch {
    return 'dark';
  }
}

export function applyTheme(theme) {
  const isLight = theme === 'light';
  if (isLight) {
    document.documentElement.setAttribute('data-theme', 'light');
    if (document.body) document.body.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.removeAttribute('data-theme');
    if (document.body) document.body.removeAttribute('data-theme');
  }
  try {
    localStorage.setItem('identityshield_theme', theme);
  } catch {}

  // Update Top Bar Power Button
  const topBtn = document.getElementById('btn-theme-toggle');
  const topIcon = document.getElementById('top-power-icon');
  const topLabel = document.getElementById('top-power-label');
  if (topBtn) {
    if (isLight) {
      topBtn.className = 'power-button relative inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold border transition-all duration-200 cursor-pointer shadow-sm bg-amber-500/15 border-amber-500/40 text-amber-700 shadow-[0_0_12px_rgba(245,158,11,0.25)]';
      if (topIcon) topIcon.textContent = '☀️';
      if (topLabel) topLabel.textContent = 'LIGHT ON';
    } else {
      topBtn.className = 'power-button relative inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-bold border transition-all duration-200 cursor-pointer shadow-sm bg-cyan-500/15 border-cyan-500/40 text-cyan-300 shadow-[0_0_14px_rgba(34,211,238,0.25)]';
      if (topIcon) topIcon.textContent = '🌙';
      if (topLabel) topLabel.textContent = 'DARK ON';
    }
  }

  // Update Sidebar Power Button
  const sideBtn = document.getElementById('btn-sidebar-theme');
  const sideTitle = document.getElementById('side-power-title');
  const sideSub = document.getElementById('side-power-sub');
  const sidePill = document.getElementById('side-power-pill');
  if (sideBtn) {
    if (isLight) {
      sideBtn.className = 'power-button-sidebar w-full flex items-center justify-between px-3 py-2 rounded-xl border transition-all duration-200 cursor-pointer shadow-sm bg-amber-500/10 border-amber-500/30 text-amber-800 hover:bg-amber-500/15';
      if (sideTitle) sideTitle.textContent = 'Light Theme';
      if (sideSub) sideSub.textContent = 'Power: ON ☀️';
      if (sidePill) {
        sidePill.className = 'text-[10px] font-mono uppercase px-2 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-700 border border-amber-500/40';
        sidePill.textContent = '☀️ ACTIVE';
      }
    } else {
      sideBtn.className = 'power-button-sidebar w-full flex items-center justify-between px-3 py-2 rounded-xl border transition-all duration-200 cursor-pointer shadow-sm bg-cyan-500/10 border-cyan-500/30 text-cyan-200 hover:bg-cyan-500/15';
      if (sideTitle) sideTitle.textContent = 'Dark Theme';
      if (sideSub) sideSub.textContent = 'Power: ON 🌙';
      if (sidePill) {
        sidePill.className = 'text-[10px] font-mono uppercase px-2 py-0.5 rounded-full font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40';
        sidePill.textContent = '🌙 ACTIVE';
      }
    }
  }

  window.dispatchEvent(new CustomEvent('theme-changed', { detail: { theme } }));
}

export function toggleTheme() {
  const current = getSavedTheme();
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
  toast(`Switched to ${next === 'light' ? 'Light' : 'Dark'} Theme`, 'info');
  return next;
}

// Immediately apply theme on script execution
if (typeof document !== 'undefined') {
  applyTheme(getSavedTheme());
}
