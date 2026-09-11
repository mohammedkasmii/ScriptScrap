// Interactive elements and their locator candidates.
//
// Every candidate is shown, including the ones that resolved to more than one
// node. Those are exactly what a generated script breaks on, so a view that
// showed only the best one would be hiding the risk rather than removing it.

import { disclosure, el, empty, pct, pill, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'UI elements';

export async function render(root) {
  const { ui_elements: elements } = await get('ui_elements');
  if (!elements.length) return void root.append(empty('No interactive elements were observed.'));

  const shaky = elements.filter((e) => e.locators.some((l) => l.stability < 1));

  root.append(el('h1', { text: 'UI elements' }));
  root.append(el('p', { class: 'subtitle', text:
    `${elements.length} element${elements.length === 1 ? '' : 's'} the operator actually `
    + 'interacted with. Stability is how often a locator resolved to exactly one node.' }));

  if (shaky.length) {
    root.append(el('section', { class: 'callout callout-warn' },
      el('h2', { text: `${shaky.length} element(s) have an unstable locator` }),
      el('p', { text:
        'A locator below 100% matched zero or several nodes on some observation. '
        + 'Anything generated from it will be flaky against a real run.' }),
    ));
  }

  root.append(el('div', {}, elements.map(block)));
}

function block(element) {
  const best = element.locators[0];
  const summary = el('span', { class: 'element-summary' },
    el('code', { class: 'tag-name', text: element.tag }),
    el('span', { class: 'element-label', text: element.label || element.text || '(no label)' }),
    element.role ? pill(element.role, 'info') : null,
    el('span', { class: 'muted', text: ` ${element.observation_count}×` }),
    (element.actions || []).map((a) => pill(a)),
    best && best.stability < 1 ? pill(`unstable ${pct(best.stability)}`, 'warn') : null,
  );

  return disclosure(summary, () => el('div', {},
    element.form ? el('p', {}, 'Form: ', el('code', { text: element.form })) : null,
    element.recommended
      ? el('p', {}, 'Recommended: ', el('code', { text: element.recommended }))
      : el('p', { class: 'warn', text: 'No locator was stable enough to recommend.' }),
    element.locators.length
      ? table(['Strategy', 'Locator', 'Resolved', 'Stability', 'Warning'],
          element.locators.map((l) => [
            l.strategy,
            el('code', { text: l.value }),
            `${l.resolved_count}/${l.sample_count}`,
            el('span', { class: l.stability < 1 ? 'status status-warning' : 'status status-ok',
              text: pct(l.stability) }),
            l.warning || '',
          ]))
      : empty('No locator candidates.'),
    evidenceList(element.evidence_ids, { label: 'Interactions' }),
  ));
}
