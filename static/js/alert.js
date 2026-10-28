import { qs } from './api.js';
import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const alertId = qs('id') || 'AL-0001';
const content = renderLayout('alerts', `Alert Detail · ${alertId}`, 'Root-cause analysis, counterfactuals, and containment');
if (content) {
  content.innerHTML = card(`Loading Alert ${alertId}`, skeleton(6));
}
