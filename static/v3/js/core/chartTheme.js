/**
 * IdentityShield v3 — Chart.js Theme for Cream Light
 * Specification: UI_DESIGN.md Section 2 (chart palette)
 */

export const CHART_PALETTE = [
  '#3D6FE0', // Sky
  '#0F8A6A', // Mint
  '#F08A4B', // Peach
  '#6D4FD8', // Lavender
  '#E0A800', // Butter
  '#E5484D', // Rose
];

export const HEATMAP_SCALE = {
  min: '#FFFDF9',
  mid: '#FFE4D3',
  max: '#E5484D',
};

export const BAND_COLORS = {
  monitor: '#94A3B8',
  step_up: '#E0A800',
  'step-up': '#E0A800',
  restrict: '#F08A4B',
  revoke: '#E5484D',
};

export function applyChartTheme(Chart) {
  if (!Chart || !Chart.defaults) return;

  Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, sans-serif";
  Chart.defaults.font.size = 12;
  Chart.defaults.color = '#4B5263'; // axis text

  // Global scale defaults
  if (Chart.defaults.scales) {
    if (Chart.defaults.scales.linear) {
      if (Chart.defaults.scales.linear.grid) Chart.defaults.scales.linear.grid.color = '#EFE8DC';
      if (Chart.defaults.scales.linear.ticks) Chart.defaults.scales.linear.ticks.color = '#4B5263';
    }
    if (Chart.defaults.scales.category) {
      if (Chart.defaults.scales.category.grid) Chart.defaults.scales.category.grid.color = '#EFE8DC';
      if (Chart.defaults.scales.category.ticks) Chart.defaults.scales.category.ticks.color = '#4B5263';
    }
  }

  // Tooltip defaults
  if (Chart.defaults.plugins && Chart.defaults.plugins.tooltip) {
    Chart.defaults.plugins.tooltip.backgroundColor = '#FFFFFF';
    Chart.defaults.plugins.tooltip.titleColor = '#1F2430';
    Chart.defaults.plugins.tooltip.bodyColor = '#1F2430';
    Chart.defaults.plugins.tooltip.borderColor = '#E8E1D6';
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
  }
}

// Auto-apply if global Chart exists
if (typeof window !== 'undefined' && window.Chart) {
  applyChartTheme(window.Chart);
}
