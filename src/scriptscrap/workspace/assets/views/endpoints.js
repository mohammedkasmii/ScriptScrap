// Endpoints, and what was inferred about each.
//
// The confidence and the observation count sit next to the route on purpose:
// a template derived from one request is a guess about a parameter's shape,
// and reading it next to one derived from forty is the difference between
// "this is the API" and "this might be".

import { clear, disclosure, el, empty, pct, pill, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Endpoints';

export async function render(root, { param } = {}) {
  const { endpoints } = await get('endpoints');
  if (!endpoints.length) return void root.append(empty('No endpoints were observed.'));

  root.append(el('h1', { text: 'Endpoints' }));
  root.append(el('p', { class: 'subtitle', text:
    `${endpoints.length} route${endpoints.length === 1 ? '' : 's'} derived from observed traffic. `
    + 'Every one cites the events behind it.' }));

  const filter = el('input', {
    type: 'search', class: 'filter', placeholder: 'Filter routes…',
    'aria-label': 'Filter routes',
  });
  root.append(filter);

  const list = el('div', { class: 'endpoint-list' });
  root.append(list);

  const draw = (needle) => {
    clear(list);
    const shown = endpoints.filter((e) =>
      !needle || `${e.method} ${e.template}`.toLowerCase().includes(needle.toLowerCase()));
    if (!shown.length) return void list.append(empty('No route matches that filter.'));
    for (const endpoint of shown) list.append(row(endpoint, endpoint.key === param));
  };

  filter.addEventListener('input', () => draw(filter.value));
  draw('');
}

function row(endpoint, open) {
  const statuses = Object.entries(endpoint.statuses || {});
  const summary = el('span', { class: 'endpoint-summary' },
    el('span', { class: `method method-${endpoint.method.toLowerCase()}`, text: endpoint.method }),
    el('code', { class: 'template', text: endpoint.template }),
    el('span', { class: 'endpoint-meta' },
      `${endpoint.observation_count}×`,
      statuses.length ? ' · ' : null,
      statuses.map(([code, n]) => pill(n > 1 ? `${code} ×${n}` : code, statusKind(code))),
      endpoint.templated ? pill('templated', 'info') : null,
      endpoint.kind !== 'rest' ? pill(endpoint.kind, 'info') : null,
      endpoint.confidence < 1 ? pill(`confidence ${pct(endpoint.confidence)}`, 'warn') : null,
    ),
  );

  return disclosure(summary, () => detail(endpoint), { open: Boolean(open) });
}

function statusKind(code) {
  const n = Number(code);
  if (n >= 500) return 'bad';
  if (n >= 400) return 'warn';
  if (n >= 300) return 'info';
  return 'ok';
}

function detail(endpoint) {
  const body = el('div', { class: 'endpoint-detail' },
    el('p', { class: 'loading', text: 'Loading…' }));

  get('endpoint', { endpoint_key: endpoint.key }).then((detail) => {
    clear(body);

    if (detail.concrete_paths.length > 1 || detail.templated) {
      body.append(el('section', {},
        el('h3', { text: 'Observed paths' }),
        detail.templated && detail.concrete_paths.length < 2
          ? el('p', { class: 'warn', text:
              'Templated from a single concrete path — the parameter is inferred '
              + 'from value shape alone, not from seeing it vary.' })
          : null,
        el('ul', { class: 'paths' },
          detail.concrete_paths.slice(0, 20).map((p) => el('li', {}, el('code', { text: p })))),
      ));
    }

    body.append(paramsSection(detail.params));
    body.append(schemasSection(detail.schemas));
    if (detail.dependencies.length) body.append(dependenciesSection(detail.dependencies));

    if (Object.keys(detail.evidence_signals || {}).length) {
      body.append(el('section', {},
        el('h3', { text: 'Why this is one endpoint' }),
        table(['Signal', 'Value'],
          Object.entries(detail.evidence_signals).map(([k, v]) => [k, String(v)])),
      ));
    }
    body.append(evidenceList(detail.evidence_ids, { label: 'Raw events' }));
  }).catch((error) => {
    clear(body);
    body.append(el('p', { class: 'error', text: error.message }));
  });

  return body;
}

function paramsSection(params) {
  if (!params || !params.length) return el('section', {},
    el('h3', { text: 'Parameters' }), empty('None observed.'));

  return el('section', {},
    el('h3', { text: 'Parameters' }),
    table(['Name', 'In', 'Type', 'Seen', 'Distinct', 'Examples'], params.map((p) => [
      el('code', { text: p.name }),
      p.location,
      p.enum_candidate ? el('span', {}, p.inferred_type, ' ', pill('enum', 'info')) : p.inferred_type,
      p.sample_count,
      p.distinct_values,
      (p.examples || []).slice(0, 3).join(', '),
    ])),
  );
}

function schemasSection(schemas) {
  if (!schemas || !schemas.length) return el('section', {},
    el('h3', { text: 'Schemas' }), empty('No body was observed on this route.'));

  return el('section', {},
    el('h3', { text: 'Schemas' }),
    schemas.map((schema) => {
      const label = schema.direction === 'response'
        ? `response ${schema.status ?? ''}`.trim() : 'request';
      const summary = el('span', {},
        el('strong', { text: label }),
        el('span', { class: 'muted', text: ` · ${schema.sample_count} sample${schema.sample_count === 1 ? '' : 's'} · ${schema.root_type}` }),
        schema.sample_count < 3
          ? pill('thin sample', 'warn') : null,
      );
      return disclosure(summary, () => el('div', {},
        schema.sample_count < 3 ? el('p', { class: 'warn', text:
          'Fewer than three observations. Treat optionality and enum candidates '
          + 'as unproven — a field absent once may simply not have been sent.' }) : null,
        table(['Field', 'Type', 'Present', 'Optional', 'Format', 'Examples'],
          schema.fields.map((f) => [
            el('code', { text: f.path }),
            (f.types || []).join(' | ') || f.inferred_type,
            `${f.present_count}/${f.sample_count}`,
            f.observed_optional ? pill('optional', 'warn') : '',
            f.inferred_format || '',
            (f.examples || []).slice(0, 2).map((e) => String(e)).join(', '),
          ])),
        evidenceList(schema.evidence_ids, { label: 'Bodies observed' }),
      ));
    }),
  );
}

function dependenciesSection(deps) {
  return el('section', {},
    el('h3', { text: 'Value flow' }),
    el('p', { class: 'hint', text:
      'A value observed here was also observed there. Correlation, not proof '
      + 'of causation.' }),
    table(['From', 'Field', 'To', 'Field', 'Mechanism', 'Confidence'], deps.map((d) => [
      el('code', { text: d.source_endpoint }),
      el('code', { text: d.source_field }),
      el('code', { text: d.target_endpoint }),
      el('code', { text: d.target_field }),
      d.mechanism,
      pct(d.confidence),
    ])),
  );
}
