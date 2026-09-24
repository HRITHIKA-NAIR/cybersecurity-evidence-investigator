// Executed before bundling and again when preparing public HTML.
export function validatePublicConfig(env) {
  const allowed = new Set(['VITE_API_URL', 'VITE_SUPABASE_URL', 'VITE_SUPABASE_PUBLISHABLE_KEY']);
  for (const name of Object.keys(env)) {
    if (name.startsWith('VITE_') && !allowed.has(name)) {
      throw new Error('Unapproved browser environment variable: ' + name + '. Review it before adding it to the public allow-list.');
    }
  }
  const key = env.VITE_SUPABASE_PUBLISHABLE_KEY || '';
  if (key && !key.startsWith('sb_publishable_')) {
    let payload;
    try { payload = JSON.parse(Buffer.from(key.split('.')[1], 'base64url').toString()); } catch { /* Reject below. */ }
    if (key.split('.').length !== 3 || payload?.role !== 'anon') {
      throw new Error('The browser requires a Supabase publishable key or legacy anon key. Secret and service-role keys are forbidden.');
    }
  }
  for (const name of ['VITE_API_URL', 'VITE_SUPABASE_URL']) {
    if (!env[name]) continue;
    let url;
    try { url = new URL(env[name]); } catch { throw new Error(name + ' must be a valid origin.'); }
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if ((!local && url.protocol !== 'https:') || !['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      throw new Error(name + ' must be a plain HTTPS origin (HTTP is allowed only on localhost).');
    }
  }
}
