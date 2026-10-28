import { renderLayout } from './layout.js';
import { card, skeleton } from './ui.js';

const content = renderLayout('audit', 'Audit Log', 'Cryptographically verified tamper-evident decision ledger');
if (content) {
  content.innerHTML = card('Loading Audit Ledger', skeleton(6));
}
