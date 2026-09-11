// Tables and dynamic data.
//
// The tables the operator worked, reconstructed from the interactions: identity
// and caption, the columns, the rows actually observed, the row actions, and
// the sort/filter/paginate operations performed. Rows are the ones the operator
// touched, not every row the table ever held. Each table drills through to the
// raw events.

import { disclosure, el, empty, pill, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Tables';

export async function render(root) {
  let body;
  try {
    body = await get('tables');
  } catch (error) {
    return void root.append(
      el('h1', { text: 'Tables' }),
      el('p', { class: 'empty', text: error.message }),
    );
  }
  const tables = body.tables;

  root.append(el('h1', { text: 'Tables' }));
  root.append(el('p', { class: 'subtitle', text:
    `${tables.length} table${tables.length === 1 ? '' : 's'} the operator worked. `
    + 'Rows shown are the ones actually touched, not every row the table held.' }));

  if (!tables.length) return void root.append(empty('No tables were interacted with.'));
  root.append(el('div', {}, tables.map(card)));
}

function card(t) {
  const summary = el('span', { class: 'segment-summary' },
    el('code', { class: 'segment-label', text: t.table_id || t.table_key }),
    t.caption ? el('span', { class: 'muted', text: t.caption }) : null,
    pill(`${t.rows.length} row${t.rows.length === 1 ? '' : 's'}`),
    ...Object.entries(t.operations || {}).map(([op, n]) => pill(`${op} ${n}`, 'info')),
  );

  return disclosure(summary, () => el('div', {},
    t.row_actions && t.row_actions.length
      ? el('p', { class: 'segment-kv' },
          el('span', { class: 'segment-key', text: 'Row actions: ' }),
          ...t.row_actions.map((a) => pill(a)))
      : null,
    t.rows.length
      ? table(
          ['Row', ...(t.columns || []).map((c) => c || '—')],
          t.rows.map((r) => [String(r.row_id ?? r.row_index ?? ''), ...(r.cells || [])]))
      : empty('No rows were observed.'),
    evidenceList(t.evidence_ids, { label: 'Events' }),
  ));
}
