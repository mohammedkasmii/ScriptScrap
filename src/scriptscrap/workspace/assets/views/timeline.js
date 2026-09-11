// The session, in the order it happened.
//
// Ordered by `seq` and never by timestamp: sensors deliver over different
// channels -- the runtime probe batches over an IPC binding while Playwright
// events arrive from the driver -- so their wall clocks disagree and `seq` is
// the only total order the spine guarantees.
//
// Rows are envelopes. A payload is fetched when a row is opened, which is what
// makes scrolling a nine-thousand-event session cost nothing.

import { clear, el, empty, shortTime } from '../lib/dom.js';
import { eventCard } from '../lib/evidence.js';
import { get } from '../lib/api.js';

export const title = 'Timeline';

// Named groups, because "show me what the user did" is the question people
// actually ask; the raw type list is available beside it.
const GROUPS = {
  User: ['user_click', 'user_dblclick', 'user_rightclick', 'user_input',
    'user_change', 'user_submit', 'user_key'],
  Network: ['http_request', 'http_response', 'http_failed',
    'runtime_fetch', 'runtime_xhr', 'runtime_beacon', 'runtime_form_submit'],
  Navigation: ['page_opened', 'page_closed', 'popup_opened', 'frame_attached',
    'frame_detached', 'frame_navigated', 'navigation_committed', 'runtime_history'],
  DOM: ['dom_snapshot', 'dom_mutation', 'html_snapshot', 'screenshot'],
  Storage: ['storage_snapshot', 'storage_change', 'cookie_changed', 'cookie_deleted'],
  WebSocket: ['ws_open', 'ws_frame_sent', 'ws_frame_received', 'ws_close', 'ws_error'],
  Problems: ['console_message', 'page_exception', 'sensor_error', 'capture_gap'],
};

export async function render(root) {
  const state = { types: new Set(), sources: new Set(), cursor: null, done: false };

  root.append(el('h1', { text: 'Timeline' }));
  const subtitle = el('p', { class: 'subtitle' });
  root.append(subtitle);

  const first = await get('timeline', { limit: 1 });
  const facets = first.facets;

  const controls = el('div', { class: 'filters' });
  root.append(controls);

  const rows = el('div', { class: 'timeline' });
  root.append(rows);

  const more = el('button', { class: 'more', text: 'Load more' });
  const status = el('p', { class: 'timeline-status' });
  root.append(more, status);

  const reload = async () => {
    state.cursor = null;
    state.done = false;
    clear(rows);
    await loadPage();
  };

  const loadPage = async () => {
    more.disabled = true;
    try {
      const body = await get('timeline', {
        limit: 200,
        after_seq: state.cursor ?? '',
        types: [...state.types].join(','),
        sources: [...state.sources].join(','),
      });
      for (const row of body.rows) rows.append(eventRow(row));
      state.cursor = body.next_seq;
      state.done = body.next_seq === null;
      subtitle.textContent =
        `${body.total.toLocaleString()} event${body.total === 1 ? '' : 's'} match`
        + `${state.types.size || state.sources.size ? ' this filter' : ''}.`;
      status.textContent = state.done
        ? `Showing all ${rows.childElementCount.toLocaleString()}.`
        : `Showing ${rows.childElementCount.toLocaleString()} of ${body.total.toLocaleString()}.`;
      more.hidden = state.done;
      if (!body.rows.length && state.done) rows.append(empty('Nothing matches this filter.'));
    } catch (error) {
      rows.append(el('p', { class: 'error', text: error.message }));
    } finally {
      more.disabled = false;
    }
  };

  // Group chips, then source chips. Only types this session actually contains
  // are offered, so a filter can never promise something that is not there.
  for (const [group, types] of Object.entries(GROUPS)) {
    const present = types.filter((t) => facets.types[t]);
    if (!present.length) continue;
    const count = present.reduce((sum, t) => sum + facets.types[t], 0);
    controls.append(chip(`${group} (${count.toLocaleString()})`, () => {
      const active = present.every((t) => state.types.has(t));
      for (const t of present) active ? state.types.delete(t) : state.types.add(t);
      return !active;
    }, reload));
  }
  controls.append(el('span', { class: 'filter-sep', text: 'source' }));
  for (const [source, count] of Object.entries(facets.sources)) {
    controls.append(chip(`${source} (${count.toLocaleString()})`, () => {
      const active = state.sources.has(source);
      active ? state.sources.delete(source) : state.sources.add(source);
      return !active;
    }, reload));
  }

  more.addEventListener('click', loadPage);
  await loadPage();
}

function chip(label, toggle, onChange) {
  const button = el('button', { class: 'chip', text: label, 'aria-pressed': 'false' });
  button.addEventListener('click', async () => {
    const active = toggle();
    button.classList.toggle('chip-on', active);
    button.setAttribute('aria-pressed', String(active));
    await onChange();
  });
  return button;
}

function eventRow(row) {
  const detail = el('div', { class: 'timeline-payload' });
  let loaded = false;

  const head = el('button', { class: 'timeline-head' },
    el('span', { class: 'ts-seq', text: `#${row.seq}` }),
    el('span', { class: 'ts-time', text: shortTime(row.t_wall) }),
    el('span', { class: `tag tag-${row.source}`, text: row.source }),
    el('span', { class: 'ts-type', text: row.type }),
    row.page_id ? el('span', { class: 'ts-page', text: row.page_id }) : null,
  );

  head.addEventListener('click', async () => {
    const open = detail.classList.toggle('open');
    if (!open || loaded) return;
    loaded = true;
    detail.append(el('p', { class: 'loading', text: 'Loading…' }));
    try {
      const { event } = await get('event', { event_id: row.event_id });
      clear(detail);
      detail.append(eventCard(event));
    } catch (error) {
      clear(detail);
      detail.append(el('p', { class: 'error', text: error.message }));
    }
  });

  return el('div', { class: 'timeline-row' }, head, detail);
}
