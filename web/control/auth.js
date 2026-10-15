export let session = null;
function signedOut() { session = null; window.dispatchEvent(new Event('lattice:signed-out')); }
export async function loadSession() {
  const response = await fetch('/api/v1/auth/session', {credentials: 'same-origin', cache: 'no-store'});
  if (!response.ok) { signedOut(); return null; }
  session = await response.json(); return session;
}
export async function login(username, password) {
  const response = await fetch('/api/v1/auth/login', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username, password})});
  if (!response.ok) throw new Error(response.status === 429 ? 'Too many attempts. Retry later.' : 'Sign in failed. Check your credentials.');
  session = await response.json(); return session;
}
export async function authenticatedFetch(path, init = {}) {
  if (typeof path !== 'string' || !path.startsWith('/api/')) throw new Error('A same-origin API path is required');
  const headers = new Headers(init.headers || {});
  if (/^\/api\/v1\/operator\/(jobs|runtimes|artifacts)(\/|$)/.test(path)) {
    const master = document.getElementById('workload-master')?.value;
    if(master) headers.set('X-Lattice-Master-Id',master);
    else if(!['GET','HEAD'].includes((init.method || 'GET').toUpperCase())) throw new Error('Choose the target master before managing workloads.');
  }
  if (session && !['GET', 'HEAD'].includes((init.method || 'GET').toUpperCase())) headers.set('X-Lattice-CSRF', session.csrf_token);
  const response = await fetch(path, {...init, headers, credentials: 'same-origin', cache: 'no-store'});
  if (response.status === 401) signedOut();
  return response;
}
export async function logout() {
  try { await authenticatedFetch('/api/v1/auth/logout', {method: 'POST'}); } finally { signedOut(); }
}
