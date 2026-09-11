// The drill-through: from a conclusion to the raw events behind it.
//
// This is the component the whole workspace exists for. Every derived record
// carries `evidence_ids`, and every one of them has to be openable, or the
// workspace is just the retired JSON files with a stylesheet.
//
// Events load on expand, not on render. A page listing thirty endpoints cites
// hundreds of events between them, and fetching all of those to draw a list
// nobody has opened would make the index pointless.

import { clear, disclosure, el, shortTime } from './dom.js';
import { get, hasEvidence } from './api.js';

/** A `<details>` that fetches its events the first time it is opened. */
export function evidenceList(eventIds, { label = 'Evidence' } = {}) {
  const ids = eventIds || [];
  if (!ids.length) {
    return el('p', { class: 'evidence-none', text: 'No evidence cited.' });
  }
  if (!hasEvidence()) {
    // A sanitised export cites event ids for a log the recipient does not
    // have. Offering a disclosure that 409s on open would be an affordance
    // that exists to fail; saying so once is the honest version.
    return el('p', { class: 'evidence-none', text:
      `${ids.length} event${ids.length === 1 ? '' : 's'} support this. The raw `
      + 'events stay in the local session directory; this sanitised export '
      + 'carries derived knowledge only.' });
  }

  const summary = el('span', {},
    el('span', { class: 'evidence-label', text: label }),
    el('span', { class: 'evidence-count', text: `${ids.length} event${ids.length === 1 ? '' : 's'}` }),
  );

  return disclosure(summary, () => {
    const body = el('div', { class: 'evidence-body' }, el('p', { class: 'loading', text: 'Loading evidence…' }));
    loadEvents(ids).then((events) => {
      clear(body);
      if (!events.length) {
        body.append(el('p', { class: 'empty', text: 'These events are not in the index.' }));
        return;
      }
      if (events.length < ids.length) {
        // Said plainly rather than shown as a shorter list: a partial
        // evidence set changes how much the conclusion is worth.
        body.append(el('p', { class: 'warn', text:
          `${ids.length - events.length} of ${ids.length} cited events are missing from the log.` }));
      }
      for (const event of events) body.append(eventCard(event));
    }).catch((error) => {
      clear(body);
      body.append(el('p', { class: 'error', text: error.message }));
    });
    return body;
  });
}

async function loadEvents(ids) {
  // The API caps a batch; a heavily-observed endpoint can cite more than that.
  const chunks = [];
  for (let i = 0; i < ids.length; i += 200) chunks.push(ids.slice(i, i + 200));
  const results = await Promise.all(
    chunks.map((chunk) => get('events', { ids: chunk.join(',') })),
  );
  return results.flatMap((r) => r.events);
}

export function eventCard(event) {
  return el('article', { class: 'event-card' },
    el('header', { class: 'event-head' },
      el('code', { class: 'event-id', text: event.event_id }),
      el('span', { class: `tag tag-${event.source}`, text: event.source }),
      el('span', { class: 'event-type', text: event.type }),
      el('span', { class: 'event-seq', text: `#${event.seq}` }),
      el('span', { class: 'event-time', text: shortTime(event.t_wall) }),
      event.page_id ? el('span', { class: 'event-page', text: event.page_id }) : null,
    ),
    payloadBlock(event.payload),
  );
}

/** Pretty-printed payload. `textContent`, never markup. */
export function payloadBlock(payload) {
  if (!payload || Object.keys(payload).length === 0) {
    return el('p', { class: 'empty', text: 'No payload.' });
  }
  const reduced = payload.evidence_reduced === true;
  return el('div', { class: 'payload' },
    reduced ? el('p', { class: 'warn', text:
      'Out of scope: this event was reduced to metadata at capture time. '
      + 'Query strings, bodies and values were never recorded.' }) : null,
    el('pre', { class: 'payload-json' },
      el('code', { text: JSON.stringify(payload, null, 2) })),
  );
}

/** An inline "open this one event" link, for a single cited id. */
export function evidenceLink(eventId) {
  const wrap = el('span', { class: 'evidence-inline' });
  const button = el('button', {
    class: 'link',
    text: eventId,
    onclick: async () => {
      button.disabled = true;
      try {
        const { event } = await get('event', { event_id: eventId });
        wrap.append(eventCard(event));
      } catch (error) {
        wrap.append(el('p', { class: 'error', text: error.message }));
      }
    },
  });
  wrap.append(button);
  return wrap;
}
