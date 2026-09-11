// Generated starting points, from the derived model.
//
// The copy button is here rather than a download link because the workspace is
// read-only: nothing it does should put a file on disk. `scriptscrap generate`
// is the command that writes one, and it is named on the page.

import { clear, el, empty } from '../lib/dom.js';
import { get } from '../lib/api.js';

export const title = 'Generate';

const KINDS = [
  ['client', 'HTTP client', 'An httpx client with a method per observed route.'],
  ['playwright', 'Playwright script', 'The observed workflow, replayed with the most stable locators.'],
];

export async function render(root) {
  root.append(el('h1', { text: 'Generate' }));
  root.append(el('p', { class: 'subtitle', text:
    'Derived suggestions, not specifications. Each describes one observed '
    + 'session: routes nobody visited are not in it, and a parameter nobody '
    + 'varied is inferred from a single value.' }));

  root.append(el('section', { class: 'callout callout-warn' },
    el('h2', { text: 'No credentials are generated' }),
    el('p', { text:
      'The capture records credential-bearing headers by name and never by '
      + 'value, so nothing generated here can carry the session it was derived '
      + 'from. Supply credentials at runtime via SCRIPTSCRAP_AUTH_HEADERS.' }),
  ));

  for (const [kind, heading, blurb] of KINDS) {
    root.append(panel(kind, heading, blurb));
  }
}

function panel(kind, heading, blurb) {
  const body = el('div', {}, el('p', { class: 'loading', text: 'Generating…' }));
  const section = el('section', { class: 'panel' },
    el('h2', { text: heading }),
    el('p', { class: 'hint', text: blurb }),
    body,
  );

  get('generate', { kind }).then((data) => {
    clear(body);
    if (!data.source) return void body.append(empty('Nothing to generate.'));

    const copy = el('button', { class: 'more', text: 'Copy' });
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(data.source);
        copy.textContent = 'Copied';
        setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
      } catch {
        copy.textContent = 'Select the text and copy';
      }
    });

    body.append(
      el('p', { class: 'muted' },
        el('code', { text: data.filename }), ' · ',
        `${data.endpoints} endpoint(s), ${data.states} state(s)`,
        data.auth_headers.length ? ` · auth: ${data.auth_headers.join(', ')}` : null,
      ),
      el('p', { class: 'hint' }, 'Write it to disk with ',
        el('code', { text: `scriptscrap generate ${kind} <session>` })),
      copy,
      el('pre', { class: 'payload-json' }, el('code', { text: data.source })),
    );
  }).catch((error) => {
    clear(body);
    body.append(el('p', { class: 'error', text: error.message }));
  });

  return section;
}
