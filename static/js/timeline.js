import { qs } from './api.js';
import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const sessionId = qs('session') || 'current';
const content = renderLayout('timeline', `Session Timeline · ${sessionId}`, 'Step-by-step session attack activity replay');
if (content) {
  content.innerHTML = card(`Loading Timeline for ${sessionId}`, skeleton(6));
}
