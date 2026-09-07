// Where the application can be, and how it gets there.

import { el, empty, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { draw } from '../lib/graph.js';
import { get } from '../lib/api.js';

export const title = 'States';

export async function render(root) {
  const { states, transitions } = await get('states');
  if (!states.length) return void root.append(empty('No states were reconstructed.'));

  root.append(el('h1', { text: 'Pages & states' }));
  root.append(el('p', { class: 'subtitle', text:
    `${states.length} state${states.length === 1 ? '' : 's'}, `
    + `${transitions.length} observed transition${transitions.length === 1 ? '' : 's'}. `
    + 'A state is a page shape that was actually reached, not a route that exists.' }));

  const nodes = states.map((s) => ({
    id: s.fingerprint,
    label: s.label,
    sub: s.url_pattern,
    count: s.observation_count,
  }));
  const edges = transitions.map((t) => ({
    from: t.from_state, to: t.to_state, label: t.trigger,
  }));

  const { svg, backEdges } = draw(nodes, edges, {
    onSelect: (node) => {
      const target = document.getElementById(`state-${node.id}`);
      if (target) {
        target.open = true;
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    },
  });

  root.append(el('section', { class: 'panel' },
    el('h2', { text: 'State graph' }),
    el('p', { class: 'hint', text:
      'Left to right by first reach. Dashed edges return to an earlier state — '
      + 'a login/logout cycle, most often.' }),
    backEdges.length
      ? el('p', { class: 'hint', text: `${backEdges.length} return edge(s).` })
      : null,
    el('div', { class: 'graph-scroll' }, svg),
  ));

  root.append(el('section', { class: 'panel' },
    el('h2', { text: 'States' }),
    el('div', {}, states.map(stateBlock)),
  ));

  if (transitions.length) {
    root.append(el('section', { class: 'panel' },
      el('h2', { text: 'Transitions' }),
      table(['From', 'To', 'Trigger', 'Seen', 'Evidence'], transitions.map((t) => [
        t.from_label,
        t.to_label,
        el('code', { text: t.trigger }),
        t.observation_count,
        evidenceList(t.evidence_ids, { label: 'Events' }),
      ])),
    ));
  }
}

function stateBlock(state) {
  const details = el('details', { class: 'state', id: `state-${state.fingerprint}` });
  details.append(el('summary', {},
    el('strong', { text: state.label }),
    el('code', { class: 'muted', text: state.url_pattern }),
    el('span', { class: 'muted', text: ` · seen ${state.observation_count}×` }),
  ));

  const forms = state.forms || [];
  details.append(el('div', { class: 'disclosure-body' },
    forms.length
      ? el('div', {},
          el('h3', { text: `Forms (${forms.length})` }),
          el('ul', {}, forms.map((f) => el('li', {},
            el('code', { text: typeof f === 'string' ? f : JSON.stringify(f) })))),
        )
      : el('p', { class: 'muted', text: 'No forms observed in this state.' }),
    evidenceList(state.evidence_ids, { label: 'Observations' }),
  ));
  return details;
}
