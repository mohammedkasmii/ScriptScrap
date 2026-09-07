// Every inferred body shape, in one place.
//
// The sample count is never far from the shape, because a schema derived from
// two observations is a sketch and one derived from forty is a description.

import { disclosure, el, empty, pill, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Schemas';

export async function render(root) {
  const { schemas } = await get('schemas');
  if (!schemas.length) return void root.append(empty('No request or response bodies were observed.'));

  const thin = schemas.filter((s) => s.sample_count < 3);

  root.append(el('h1', { text: 'Schemas' }));
  root.append(el('p', { class: 'subtitle', text:
    `${schemas.length} shape${schemas.length === 1 ? '' : 's'} inferred from observed bodies.` }));

  if (thin.length) {
    root.append(el('section', { class: 'callout callout-warn' },
      el('h2', { text: `${thin.length} schema(s) rest on fewer than three samples` }),
      el('p', { text:
        'Optionality and enum candidates in those are unproven. A field absent '
        + 'from one of two bodies may simply not have been sent that time.' }),
    ));
  }

  root.append(el('div', {}, schemas.map(block)));
}

function block(schema) {
  const label = schema.direction === 'response'
    ? `response ${schema.status ?? ''}`.trim() : 'request';

  const summary = el('span', { class: 'schema-summary' },
    el('code', { text: schema.endpoint_key }),
    pill(label, schema.direction === 'response' ? 'info' : null),
    el('span', { class: 'muted', text: `${schema.root_type} · ${schema.sample_count} sample${schema.sample_count === 1 ? '' : 's'} · ${schema.fields.length} field${schema.fields.length === 1 ? '' : 's'}` }),
    schema.sample_count < 3 ? pill('thin', 'warn') : null,
  );

  return disclosure(summary, () => el('div', {},
    table(['Field', 'Type', 'Present', 'Nulls', 'Optional', 'Format', 'Enum', 'Examples'],
      schema.fields.map((f) => [
        el('code', { text: f.path }),
        (f.types || []).join(' | ') || f.inferred_type,
        `${f.present_count}/${f.sample_count}`,
        f.null_count || '',
        f.observed_optional ? pill('optional', 'warn') : '',
        f.inferred_format || '',
        f.enum_candidate ? (f.enum_candidate || []).join(', ') : '',
        (f.examples || []).slice(0, 2).map((e) => String(e)).join(', '),
      ])),
    evidenceList(schema.evidence_ids, { label: 'Bodies observed' }),
  ));
}
