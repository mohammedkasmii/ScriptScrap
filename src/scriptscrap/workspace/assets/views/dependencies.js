// Value flow between endpoints.
//
// An edge says a value observed in one place was observed again in another.
// That is correlation, and the view says so: a confidence and the signals it
// was scored on sit next to every edge, because "the id came from here" is a
// hypothesis a developer will act on.

import { el, empty, pct, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { draw } from '../lib/graph.js';
import { get } from '../lib/api.js';

export const title = 'Dependencies';

export async function render(root) {
  const { nodes, dependencies } = await get('dependencies');

  root.append(el('h1', { text: 'Dependencies' }));
  if (!dependencies.length) {
    root.append(el('p', { class: 'subtitle', text:
      'No value flow was observed between endpoints.' }));
    root.append(el('p', { class: 'hint', text:
      'This is a statement about the session, not the application. A workflow '
      + 'that never re-sent a value it received produces no edges.' }));
    return;
  }

  root.append(el('p', { class: 'subtitle', text:
    `${dependencies.length} hypothesis${dependencies.length === 1 ? '' : 'es'}. `
    + 'A value seen in one response reappeared in a later request.' }));

  const graphNodes = Object.values(nodes).map((n) => ({
    id: n.key, label: n.key, count: n.observation_count || null,
  }));
  const edges = dependencies.map((d) => ({
    from: d.source_endpoint, to: d.target_endpoint, label: d.source_field,
  }));

  const { svg } = draw(graphNodes, edges);
  root.append(el('section', { class: 'panel' },
    el('h2', { text: 'Flow' }),
    el('div', { class: 'graph-scroll' }, svg),
  ));

  root.append(el('section', { class: 'panel' },
    el('h2', { text: 'Edges' }),
    el('p', { class: 'hint', text:
      'Confidence is scored on how distinctive the value was and how often the '
      + 'pairing repeated. A value that appears everywhere is weak evidence '
      + 'however many times it repeats.' }),
    el('div', {}, dependencies.map(edgeBlock)),
  ));
}

function edgeBlock(dep) {
  return el('article', { class: 'dep' },
    el('header', { class: 'dep-head' },
      el('code', { text: `${dep.source_endpoint} · ${dep.source_field}` }),
      el('span', { class: 'dep-arrow', text: '→' }),
      el('code', { text: `${dep.target_endpoint} · ${dep.target_field}` }),
      el('span', { class: 'muted', text: ` ${dep.mechanism} · ${pct(dep.confidence)}` }),
    ),
    table(['Signal', 'Value'], [
      ['repeats', dep.repeat_count],
      ['value uniqueness', dep.value_uniqueness],
      ...Object.entries(dep.evidence_signals || {}).map(([k, v]) => [k, String(v)]),
    ]),
    evidenceList(dep.evidence_ids, { label: 'Observations' }),
  );
}
