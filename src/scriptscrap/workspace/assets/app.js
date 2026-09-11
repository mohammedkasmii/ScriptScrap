// The workspace shell: session picker, nav rail, hash router.
//
// No framework and no build step. The routes below are the whole application;
// each view is a module that renders into a container and fetches what it
// needs.

import { clear, el } from './lib/dom.js';
import { get, setSession } from './lib/api.js';

import * as overview from './views/overview.js';
import * as timeline from './views/timeline.js';
import * as activities from './views/activities.js';
import * as forms from './views/forms.js';
import * as tables from './views/tables.js';
import * as endpoints from './views/endpoints.js';
import * as states from './views/states.js';
import * as elements from './views/elements.js';
import * as schemas from './views/schemas.js';
import * as dependencies from './views/dependencies.js';
import * as technology from './views/technology.js';
import * as generate from './views/generate.js';

const VIEWS = [
  ['overview', overview],
  ['timeline', timeline],
  ['activities', activities],
  ['forms', forms],
  ['tables', tables],
  ['endpoints', endpoints],
  ['states', states],
  ['elements', elements],
  ['schemas', schemas],
  ['dependencies', dependencies],
  ['technology', technology],
  ['generate', generate],
];

const byName = new Map(VIEWS);
const app = document.getElementById('app');
const content = document.getElementById('content');
const rail = document.getElementById('rail');
const picker = document.getElementById('session-picker');
const badge = document.getElementById('redaction');
const stats = document.getElementById('session-stats');

let sessions = [];

async function boot() {
  try {
    const body = await get('sessions');
    sessions = body.sessions;
  } catch (error) {
    app.hidden = false;
    clear(content).append(fatal(error));
    return;
  }

  if (!sessions.length) {
    app.hidden = false;
    clear(content).append(fatal(new Error('This workspace has no sessions.')));
    return;
  }

  clear(picker);
  for (const session of sessions) {
    picker.append(el('option', { value: session.name, text: session.name }));
  }
  picker.hidden = sessions.length < 2;
  picker.addEventListener('change', () => {
    selectSession(picker.value);
    route();
  });

  for (const [name, view] of VIEWS) {
    rail.append(el('a', { class: 'rail-link', href: `#/${name}`, dataset: { view: name },
      text: view.title }));
  }

  selectSession(sessions[0].name);
  app.hidden = false;
  window.addEventListener('hashchange', route);
  route();
}

function selectSession(name) {
  const session = sessions.find((s) => s.name === name) || sessions[0];
  setSession(session.name, session.has_evidence !== false);
  document.body.classList.toggle('no-evidence', session.has_evidence === false);
  picker.value = session.name;

  // The most important thing on the page. A session directory and its
  // sanitised export look identical in a screenshot, and only one of them is
  // safe to share.
  const unredacted = session.redaction === 'unredacted';
  badge.textContent = unredacted ? 'UNREDACTED' : 'SANITISED';
  badge.className = `badge badge-${unredacted ? 'danger' : 'safe'}`;
  badge.title = unredacted
    ? 'This is a raw capture of an authenticated session: live credentials, '
      + 'full bodies, screenshots. Do not screen-share or redistribute.'
    : 'A sanitised export: credentials removed, identifiers pseudonymised, '
      + 'no bodies or screenshots.';

  stats.textContent = `${(session.event_count || 0).toLocaleString()} events`;
}

async function route() {
  const [, name = 'overview', param] = (window.location.hash || '').split('/');
  const view = byName.get(name) || overview;

  for (const link of rail.querySelectorAll('.rail-link')) {
    link.classList.toggle('active', link.dataset.view === (byName.has(name) ? name : 'overview'));
  }

  clear(content);
  content.append(el('p', { class: 'loading', text: 'Loading…' }));
  try {
    const container = el('div', { class: `view view-${name}` });
    await view.render(container, { param: param ? decodeURIComponent(param) : null });
    clear(content).append(container);
    content.focus({ preventScroll: true });
  } catch (error) {
    clear(content).append(fatal(error));
  }
}

function fatal(error) {
  return el('div', { class: 'callout callout-critical' },
    el('h2', { text: 'Could not load this view' }),
    el('p', { text: error.message }),
    el('p', { class: 'hint', text:
      'If the evidence index is stale, re-run `scriptscrap analyze` on this '
      + 'session and reload.' }),
  );
}

boot();
