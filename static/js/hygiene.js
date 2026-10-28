import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const content = renderLayout('hygiene', 'Identity Hygiene', 'Dormant privileged credentials and toxic escalation paths');
if (content) {
  content.innerHTML = card('Loading Hygiene Audit', skeleton(6));
}
