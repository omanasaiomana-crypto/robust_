import { qs } from './api.js';
import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const identityId = qs('identity') || 'svc-report';
const content = renderLayout('graph', `Identity Graph · ${identityId}`, 'Blast radius and privilege escalation network');
if (content) {
  content.innerHTML = card(`Loading Graph for ${identityId}`, skeleton(6));
}
