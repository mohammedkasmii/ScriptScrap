// Inferred business activities.
//
// A long agency session is one recording of many unrelated tasks. This view
// shows the automatic split into probable activities -- an INTERPRETATION laid
// over the timeline, never a replacement for it. Each activity says why it
// began and how it ended, what routes, forms and endpoints it touched, and how
// confident the boundary evidence was, and every one drills through to the raw
// events behind it.

import { disclosure, el, empty, pct, pill } from '../lib/dom.js';
import { evidenceList } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Activities';

const OUTCOME_KIND = {
  form_submitted: 'ok',
  returned_to_home: 'info',
  navigated_away: 'info',
  idle: 'warn',
  session_end: 'info',
  ongoing: 'muted',
};

export async function render(root) {
  let body;
  try {
    body = await get('segments');
  } catch (error) {
    // A sanitised export has no log to re-derive from; say so plainly.
    return void root.append(
      el('h1', { text: 'Activities' }),
      el('p', { class: 'empty', text: error.message }),
    );
  }
  const segments = body.segments;

  root.append(el('h1', { text: 'Activities' }));
  root.append(el('p', { class: 'subtitle', text:
    `${segments.length} activity/activities inferred from idle gaps, form `
    + 'submissions and route structure. This is an interpretation of the '
    + 'timeline, not a rewrite of it — the ordered log stays the source of truth.' }));

  if (!segments.length) {
    return void root.append(empty('No user actions were recorded, so no activity could be inferred.'));
  }

  root.append(el('div', {}, segments.map(card)));
}

function card(seg) {
  const summary = el('span', { class: 'segment-summary' },
    el('span', { class: 'segment-index', text: `#${seg.index}` }),
    el('span', { class: 'segment-label', text: seg.label }),
    pill(`${seg.action_count} action${seg.action_count === 1 ? '' : 's'}`),
    pill(seg.outcome, OUTCOME_KIND[seg.outcome] || 'muted'),
    el('span', { class: 'muted', text: `conf ${pct(seg.confidence)}` }),
  );

  return disclosure(summary, () => el('div', {},
    kv('Began', seg.boundary_reason),
    kv('Ended', seg.outcome),
    kv('Sequence', `#${seg.start_seq} – #${seg.end_seq}`),
    seg.duration_ms != null ? kv('Duration', `${Math.round(seg.duration_ms / 1000)}s`) : null,
    listRow('Routes', seg.routes),
    listRow('Forms', seg.forms),
    listRow('Endpoints', seg.endpoints),
    actionRow(seg.action_kinds),
    evidenceList(seg.evidence_ids, { label: 'Events' }),
  ));
}

function kv(label, value) {
  return el('p', { class: 'segment-kv' },
    el('span', { class: 'segment-key', text: `${label}: ` }),
    el('code', { text: String(value) }));
}

function listRow(label, values) {
  if (!values || !values.length) return null;
  return el('p', { class: 'segment-kv' },
    el('span', { class: 'segment-key', text: `${label}: ` }),
    ...values.map((v) => el('code', { class: 'segment-chip', text: v })));
}

function actionRow(kinds) {
  const entries = Object.entries(kinds || {});
  if (!entries.length) return null;
  return el('p', { class: 'segment-kv' },
    el('span', { class: 'segment-key', text: 'Actions: ' }),
    ...entries.map(([kind, n]) => pill(`${kind} ${n}`)));
}
