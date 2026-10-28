import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const content = renderLayout('identities', 'Identities', 'Monitored human and service identities');
if (content) {
  content.innerHTML = card('Loading Identities', skeleton(6));
}
