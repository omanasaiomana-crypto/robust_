/**
 * IdentityShield v3 — Cyber Stealth Chart & Visualization Theme
 * Colors: Emerald (#10B981), Amber (#F59E0B), Tangerine (#F97316), Teal (#14B8A6), Gold (#EAB308), Crimson (#EF4444)
 * ZERO Blue, ZERO Purple. Dark contrast background with bright white labels.
 */

export const CHART_PALETTE = {
  emerald: '#10B981',
  amber: '#F59E0B',
  orange: '#F97316',
  teal: '#14B8A6',
  gold: '#EAB308',
  crimson: '#EF4444',
  series: ['#10B981', '#F59E0B', '#F97316', '#14B8A6', '#EAB308', '#EF4444'],
  grid: '#1F293D',
  text: '#F8FAFC',
  textMuted: '#94A3B8',
  tooltipBg: '#121824',
  tooltipBorder: '#2E3C57',
};

export const HEATMAP_SCALE = {
  low: '#121824',
  mid: '#F59E0B',
  high: '#EF4444',
};

export const BAND_COLORS = {
  monitor: '#64748B',
  step_up: '#F59E0B',
  'step-up': '#F59E0B',
  restrict: '#F97316',
  revoke: '#EF4444',
};

export function getChartThemeOptions() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    color: CHART_PALETTE.text,
    scales: {
      x: {
        grid: { color: CHART_PALETTE.grid, borderColor: CHART_PALETTE.grid },
        ticks: { color: CHART_PALETTE.textMuted, font: { family: 'JetBrains Mono', size: 11 } },
      },
      y: {
        grid: { color: CHART_PALETTE.grid, borderColor: CHART_PALETTE.grid },
        ticks: { color: CHART_PALETTE.textMuted, font: { family: 'JetBrains Mono', size: 11 } },
      },
    },
    plugins: {
      legend: {
        labels: { color: CHART_PALETTE.text, font: { family: 'Inter', size: 12, weight: 600 } },
      },
      tooltip: {
        backgroundColor: CHART_PALETTE.tooltipBg,
        borderColor: CHART_PALETTE.tooltipBorder,
        borderWidth: 1,
        titleColor: CHART_PALETTE.text,
        bodyColor: CHART_PALETTE.text,
        titleFont: { family: 'Inter', weight: 700 },
        bodyFont: { family: 'JetBrains Mono' },
        padding: 10,
        boxPadding: 4,
      },
    },
  };
}
