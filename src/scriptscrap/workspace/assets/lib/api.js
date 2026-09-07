// Talking to the workspace server.
//
// Same-origin only; the CSP forbids anything else. The token travels in a
// cookie set on first load, so nothing here handles it.

let currentSession = null;

export function setSession(name) {
  currentSession = name;
}

export function getSession() {
  return currentSession;
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export async function get(route, params = {}) {
  const url = new URL(`/api/${route}`, window.location.origin);
  if (currentSession) url.searchParams.set('session', currentSession);
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') continue;
    url.searchParams.set(key, String(value));
  }

  const response = await fetch(url, { credentials: 'same-origin' });
  let body;
  try {
    body = await response.json();
  } catch {
    throw new ApiError(`${response.status} ${response.statusText}`, response.status);
  }
  if (!response.ok) {
    // The server's message is the useful part -- "the index is stale, re-run
    // analyze" is an instruction, not a status code.
    throw new ApiError(body.error || `${response.status}`, response.status);
  }
  return body;
}
