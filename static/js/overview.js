import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const content = renderLayout('overview', 'Threat Overview', 'Real-time multi-agent identity threat posture');
if (content) {
  content.innerHTML = card('Loading Threat Overview', skeleton(6));
}
