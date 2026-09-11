// Forms and controls.
//
// Each form the operator used, assembled from every observation of it: the
// controls with their final values, option choices and state, the submit, and
// the request and outcome it produced. A secret field shows that something was
// entered, never the value. Every form drills through to the raw events.

import { disclosure, el, empty, pill, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Forms';

export async function render(root) {
  let body;
  try {
    body = await get('forms');
  } catch (error) {
    return void root.append(
      el('h1', { text: 'Forms' }),
      el('p', { class: 'empty', text: error.message }),
    );
  }
  const forms = body.forms;

  root.append(el('h1', { text: 'Forms' }));
  root.append(el('p', { class: 'subtitle', text:
    `${forms.length} form${forms.length === 1 ? '' : 's'} the operator used. `
    + 'A secret field shows that something was entered, never its value.' }));

  if (!forms.length) return void root.append(empty('No forms were used in this session.'));
  root.append(el('div', {}, forms.map(card)));
}

function card(form) {
  const summary = el('span', { class: 'segment-summary' },
    el('code', { class: 'segment-label', text: form.form_id || form.form_key }),
    form.method ? pill(form.method, 'info') : null,
    form.submitted ? pill('submitted', 'ok') : pill('not submitted', 'muted'),
    el('span', { class: 'muted', text: `${form.controls.length} control${form.controls.length === 1 ? '' : 's'}` }),
  );

  return disclosure(summary, () => el('div', {},
    form.action ? kv('Action', `${form.method || ''} ${form.action}`) : null,
    table(['Control', 'Type', 'Label', 'Final value', 'State'],
      form.controls.map((c) => [
        el('code', { text: c.name }),
        c.type || c.tag,
        c.label || c.placeholder || '—',
        valueCell(c),
        stateCell(c),
      ])),
    form.associated_request
      ? kv('Request', `${form.associated_request.method || ''} ${form.associated_request.path || ''}`)
      : null,
    form.outcome ? kv('Outcome', outcomeText(form.outcome)) : null,
    evidenceList(form.evidence_ids, { label: 'Events' }),
  ));
}

function valueCell(c) {
  if (c.secret) return el('span', { class: 'status status-warning', text: '(secret)' });
  const value = c.selected_label || c.final_value;
  return value == null ? '—' : el('code', { text: value });
}

function stateCell(c) {
  const bits = [];
  if (c.kind === 'combobox') bits.push('combobox');
  if (c.checked != null) bits.push(c.checked ? 'checked' : 'unchecked');
  if (c.required) bits.push('required');
  if (c.disabled) bits.push('disabled');
  if (c.readonly) bits.push('readonly');
  if (c.options && c.options.length) {
    bits.push(`${c.options.length} option(s)${c.options_complete ? '' : ' (partial)'}`);
  }
  return bits.join(', ') || '—';
}

function outcomeText(outcome) {
  if (outcome.kind === 'navigation') return `navigation → ${outcome.route}`;
  if (outcome.kind === 'response') return `response ${outcome.status}`;
  return outcome.kind;
}

function kv(label, value) {
  return el('p', { class: 'segment-kv' },
    el('span', { class: 'segment-key', text: `${label}: ` }),
    el('code', { text: String(value) }));
}
