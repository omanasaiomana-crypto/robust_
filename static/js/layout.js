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
      id: 'alerts',
      label: 'Alerts',
      href: `/alerts.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>`,
    },
    {
      id: 'identities',
      label: 'Identities',
      href: `/identities.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/></svg>`,
    },
    {
      id: 'graph',
      label: 'Identity Graph',
      href: `/graph.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z"/></svg>`,
    },
    {
      id: 'timeline',
      label: 'Timeline',
      href: `/timeline.html${querySuffix}`,
      icon: `<svg class="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
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
  ];

  app.innerHTML = `
    <div class="min-h-screen bg-bg flex flex-col md:flex-row text-ink">
      <!-- Mobile Backdrop -->
      <div id="mobile-backdrop" class="fixed inset-0 bg-black/60 z-30 hidden md:hidden"></div>

      <!-- Left Sidebar -->
      <aside id="sidebar" class="fixed inset-y-0 left-0 z-40 w-60 bg-panel border-r border-line flex flex-col transform -translate-x-full md:translate-x-0 transition-transform duration-200 ease-in-out md:static md:h-screen md:sticky md:top-0">
        <!-- Logo -->
        <div class="h-16 px-5 border-b border-line flex items-center gap-3 flex-shrink-0">
          <div class="w-8 h-8 rounded-lg bg-brand/15 border border-brand/30 flex items-center justify-center text-brand">
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
                ? 'bg-panel2 text-ink font-medium border-l-2 border-brand shadow-sm'
                : 'text-muted hover:bg-panel2/60 hover:text-ink';
              return `
                <a href="${item.href}" class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${activeClass}">
                  ${item.icon}
                  <span>${esc(item.label)}</span>
                </a>
              `;
            })
            .join('')}
        </nav>

        <!-- Sidebar Footer -->
        <div class="p-4 border-t border-line text-xs text-muted flex items-center justify-between">
          <span class="font-mono">Track 2: Zero Trust</span>
          <span class="px-1.5 py-0.5 rounded bg-panel2 text-[10px] font-mono border border-line">v1.0</span>
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

            <!-- Re-run Pipeline Button -->
            <button id="btn-rerun" class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-brand/10 hover:bg-brand/20 text-brand border border-brand/30 transition-colors">
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
