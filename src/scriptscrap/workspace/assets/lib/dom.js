// Building blocks for the workspace UI.
//
// `el` takes text, never markup. That is deliberate and load-bearing: every
// string this application renders -- URLs, element labels, console output,
// response bodies -- was captured from somebody else's web application. An
// `innerHTML` anywhere in this codebase would let a captured page script
// itself into the viewer, and the viewer is the window holding an
// authenticated session's evidence.
//
// There is a test that greps these assets for innerHTML.

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on')) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'text') node.textContent = String(value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/** A labelled figure, the workspace's most repeated shape. */
export function stat(label, value, extra) {
  return el('div', { class: 'stat' },
    el('span', { class: 'stat-value', text: value }),
    el('span', { class: 'stat-label', text: label }),
    extra ? el('span', { class: 'stat-extra', text: extra }) : null,
  );
}

export function pill(text, kind) {
  return el('span', { class: `pill${kind ? ' pill-' + kind : ''}`, text });
}

/** A collapsible section. Closed by default keeps a long page readable. */
export function disclosure(summaryNode, buildBody, { open = false } = {}) {
  const details = el('details', open ? { open: true } : {});
  details.append(el('summary', {}, summaryNode));
  let built = false;
  const body = el('div', { class: 'disclosure-body' });
  details.append(body);
  const build = () => {
    if (built) return;
    built = true;
    body.append(buildBody());
  };
  if (open) build();
  details.addEventListener('toggle', () => { if (details.open) build(); });
  return details;
}

export function table(headers, rows) {
  return el('div', { class: 'table-scroll' },
    el('table', {},
      el('thead', {}, el('tr', {}, headers.map((h) => el('th', { text: h })))),
      el('tbody', {}, rows.map((cells) => el('tr', {}, cells.map(
        (c) => el('td', {}, c instanceof Node ? c : String(c ?? '')),
      )))),
    ),
  );
}

export function empty(message) {
  return el('p', { class: 'empty', text: message });
}

/** Percentage with one decimal, for stability and confidence. */
export function pct(value) {
  if (value === null || value === undefined) return '—';
  return `${(Number(value) * 100).toFixed(0)}%`;
}

export function bytes(n) {
  if (!n && n !== 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = Number(n);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function shortTime(isoString) {
  if (!isoString) return '—';
  const t = String(isoString);
  const match = t.match(/T(\d\d:\d\d:\d\d)(\.\d+)?/);
  return match ? match[1] : t;
}
