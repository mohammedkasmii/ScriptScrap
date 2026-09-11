// What this session is, what was observed, and what was NOT.
//
// The counts are the least important thing here. A capture gap or a sensor
// blind spot says a conclusion elsewhere in the workspace rests on evidence
// nobody collected, so findings come before the figures and criticals come
// before everything.

import { el, empty, stat, table } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { bytes } from '../lib/dom.js';
import { get } from '../lib/api.js';

const COUNT_LABELS = {
  endpoints: 'Endpoints',
  schemas: 'Schemas',
  dependencies: 'Dependencies',
  ui_elements: 'UI elements',
  states: 'States',
  state_transitions: 'Transitions',
  technologies: 'Technologies',
  events: 'Events',
};

export const title = 'Overview';

export async function render(root) {
  const data = await get('session');

  root.append(el('h1', { text: data.name }));
  root.append(el('p', { class: 'subtitle' },
    `Session ${data.session_id ?? '—'} · analysed ${data.analysed_at ?? '—'} · `,
    `${data.event_count.toLocaleString()} events · ${bytes(data.log_size)} log`,
  ));

  const criticals = data.findings.filter((f) => f.severity === 'critical');
  if (criticals.length) {
    root.append(el('section', { class: 'callout callout-critical' },
      el('h2', { text: 'Evidence you do not have' }),
      el('p', { text:
        'These say a conclusion in this workspace rests on something no sensor '
        + 'recorded. Read them before trusting anything below.' }),
      el('ul', {}, criticals.map((f) => el('li', {},
        el('strong', { text: f.kind }), ' — ', f.message,
      ))),
    ));
  }

  root.append(el('section', { class: 'stats' },
    Object.entries(COUNT_LABELS)
      .filter(([key]) => key in data.counts)
      .map(([key, label]) => stat(label, data.counts[key].toLocaleString())),
  ));

  root.append(section('Capture health', healthBlock(data)));
  root.append(section('Findings', findingsBlock(data.findings)));
  root.append(section('Event mix', mixBlock(data)));
  root.append(section('Conditions of capture', manifestBlock(data)));
}

function section(heading, body) {
  return el('section', { class: 'panel' }, el('h2', { text: heading }), body);
}

function healthBlock(data) {
  if (!data.manifest_present) {
    return el('div', {},
      el('p', { class: 'warn', text:
        'No session_manifest.json. The manifest records the browser build, the '
        + 'addon configuration, the scope policy and the known blind spots — it '
        + 'is how a reader judges everything else. An interrupted session may '
        + 'never have written one.' }),
    );
  }
  const health = data.health;
  if (!health || !health.sensors) return empty('The manifest records no capture health.');

  return el('div', {},
    el('p', { class: 'overall' }, 'Overall: ', el('strong', { text: health.overall ?? 'unknown' })),
    table(['Sensor', 'Status', 'Why'], health.sensors.map((s) => [
      s.sensor,
      el('span', { class: `status status-${String(s.status).split('_')[0]}`, text: s.status }),
      (s.reasons || []).join('; '),
    ])),
    (health.notes || []).length
      ? el('ul', { class: 'notes' }, health.notes.map((n) => el('li', { text: n })))
      : null,
  );
}

function findingsBlock(findings) {
  if (!findings.length) return empty('No findings.');
  return el('div', {}, findings.map((f) => el('div', { class: `finding finding-${f.severity}` },
    el('header', {},
      el('span', { class: `status status-${f.severity}`, text: f.severity }),
      el('span', { class: 'finding-kind', text: f.kind }),
      f.count > 1 ? el('span', { class: 'finding-count', text: `×${f.count}` }) : null,
    ),
    el('p', { text: f.message }),
    evidenceList(f.evidence_ids, { label: 'Occurrences' }),
  )));
}

function mixBlock(data) {
  const types = Object.entries(data.events_by_type);
  if (!types.length) return empty('No events indexed.');
  const max = Math.max(...types.map(([, n]) => n));
  return el('div', {},
    el('div', { class: 'bars' }, types.map(([type, n]) => el('div', { class: 'bar-row' },
      el('span', { class: 'bar-label', text: type }),
      el('span', { class: 'bar-track' },
        el('span', { class: 'bar-fill', style: `width:${(n / max) * 100}%` })),
      el('span', { class: 'bar-value', text: n.toLocaleString() }),
    ))),
    el('p', { class: 'by-source' }, 'By source: ',
      Object.entries(data.events_by_source)
        .map(([s, n]) => `${s} ${n.toLocaleString()}`).join(' · ')),
  );
}

function manifestBlock(data) {
  if (!data.manifest_present) return empty('No manifest.');
  const rows = [];
  if (data.browser) {
    rows.push(['Browser build', data.browser.build ?? data.browser.version ?? '—']);
    if ('default_addons_excluded' in data.browser) {
      rows.push(['Addons excluded', (data.browser.default_addons_excluded || []).join(', ') || 'none']);
    }
    if ('addon_request_filtering_active' in data.browser) {
      rows.push(['Addon request filtering', String(data.browser.addon_request_filtering_active)]);
    }
  }
  if (data.scope) {
    rows.push(['In-scope roots', (data.scope.in_scope_roots || []).join(', ')]);
    rows.push(['Out-of-scope policy', data.scope.out_of_scope_policy ?? '—']);
  }
  if (data.event_spine) {
    rows.push(['Event spine', data.event_spine.mode ?? '—']);
  }

  return el('div', {},
    rows.length ? table(['', ''], rows) : empty('The manifest records no capture conditions.'),
    (data.known_blind_spots || []).length ? el('div', { class: 'blind-spots' },
      el('h3', { text: 'Known blind spots' }),
      el('p', { class: 'hint', text:
        'Recorded by the capture itself. These are limits of observation, not '
        + 'findings about the application.' }),
      el('ul', {}, data.known_blind_spots.map((b) => el('li', { text: b }))),
    ) : null,
  );
}
