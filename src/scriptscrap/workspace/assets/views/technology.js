// What the application appears to be built on.
//
// Fingerprints are inference from observable signals -- a header, a cookie
// name, a global. Every one shows the signals it was matched on, because a
// framework guessed from one cookie name is worth less than one confirmed by
// four independent signals, and the reader has to be able to tell.

import { el, empty, pct, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Technology';

export async function render(root) {
  const { technologies } = await get('technologies');

  root.append(el('h1', { text: 'Technology' }));
  if (!technologies.length) {
    root.append(empty('No technology fingerprints matched.'));
    root.append(el('p', { class: 'hint', text:
      'Absence of a match is not absence of a framework — it means nothing '
      + 'observed in this session carried a signal the fingerprints know.' }));
    return;
  }

  root.append(el('p', { class: 'subtitle', text:
    `${technologies.length} fingerprint${technologies.length === 1 ? '' : 's'} matched.` }));

  root.append(table(['Technology', 'Category', 'Confidence', 'Signals', 'Evidence'],
    technologies.map((t) => [
      el('strong', { text: t.name }),
      t.category,
      el('span', {
        class: t.confidence < 0.6 ? 'status status-warning' : 'status status-ok',
        text: pct(t.confidence),
      }),
      el('ul', { class: 'signals' }, (t.signals || []).map((s) => el('li', { text: s }))),
      evidenceList(t.evidence_ids, { label: 'Events' }),
    ])));
}
