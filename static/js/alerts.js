import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const content = renderLayout('alerts', 'Alert Queue', 'Prioritized session-level identity threats');
if (content) {
  content.innerHTML = card('Loading Alerts', skeleton(6));
}
