import { readdir, readFile, writeFile } from 'node:fs/promises';
import { loadEnv } from 'vite';
import { validatePublicConfig } from './public-config.mjs';
const env = { ...loadEnv('production', process.cwd(), ''), ...process.env };
validatePublicConfig(env);
const ready = env.LAUNCH_READY === 'true';
const site = new URL(env.SITE_URL || 'http://localhost:5173');
const email = env.SUPPORT_EMAIL || '';
const operator = env.OPERATOR_NAME || '';
const publicKey = env.VITE_SUPABASE_PUBLISHABLE_KEY || '';
if (site.username || site.password || site.search || site.hash || site.pathname !== '/') throw new Error('SITE_URL must be a plain site origin.');
if (ready && (site.protocol !== 'https:' || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email) || !operator.trim())) throw new Error('Launch needs HTTPS SITE_URL, a monitored SUPPORT_EMAIL and OPERATOR_NAME.');
if (ready) {
  for (const key of ['VITE_API_URL', 'VITE_SUPABASE_URL']) {
    if (!env[key] || new URL(env[key]).protocol !== 'https:') throw new Error('Launch needs an HTTPS ' + key);
  }
  if (!publicKey) throw new Error('Launch needs a Supabase publishable key.');
}
const escape = value => value.replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
// Scan emitted text for actual configured secret values and common credential forms.
// Report the filename only; never echo a match or a secret in build logs.
const secrets = ['DATABASE_URL', 'GEMINI_API_KEY', 'VIRUSTOTAL_API_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']
  .map(name => env[name]).filter(value => value && value.length >= 8);
async function checkBundle(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = directory + '/' + entry.name;
    if (entry.isDirectory()) { await checkBundle(path); continue; }
    if (!/\.(js|css|html|json|map|txt|xml)$/.test(path)) continue;
    const text = await readFile(path, 'utf8');
    const privilegedJWT = [...text.matchAll(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g)].some(([jwt]) => {
      try { return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')).role === 'service_role'; } catch { return false; }
    });
    if (privilegedJWT || /sb_secret_[A-Za-z0-9_-]{12,}|postgres(?:ql)?:\/\/[^\s"'<>]+:[^\s"'<>]+@|AIza[A-Za-z0-9_-]{30,}/.test(text) || secrets.some(secret => text.includes(secret))) {
      throw new Error('Potential server credential in ' + path + '. Build blocked; remove it and rotate any exposed credential.');
    }
  }
}
await checkBundle('dist');
const contact = email ? '<a href="mailto:' + escape(email) + '">' + escape(email) + '</a>' : 'Contact has not been configured. This preview is not open for public submissions.';
const pages = (await readdir('dist')).filter(name => name.endsWith('.html'));
for (const name of pages) {
  let html = await readFile('dist/' + name, 'utf8');
  html = html.replaceAll('__OPERATOR__', escape(operator || 'Operator details pending'))
    .replaceAll('__CONTACT__', contact).replaceAll('https://evidence-m0j5.onrender.com', site.origin)
    .replaceAll('__SITE_URL__', site.origin);
  if (!ready || name === '404.html') html = html.replace('</head>', '<meta name="robots" content="noindex,nofollow"></head>');
  await writeFile('dist/' + name, html);
}
const indexed = ['/', '/guide.html', '/phishing-checker.html', '/privacy.html', '/terms.html', '/data-deletion.html', '/acceptable-use.html', '/copyright.html'];
await writeFile('dist/sitemap.xml', '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + (ready ? indexed.map(path => '<url><loc>' + site.origin + path + '</loc></url>').join('') : '') + '</urlset>\n');
await writeFile('dist/robots.txt', 'User-agent: *\n' + (ready ? 'Allow: /\nSitemap: ' + site.origin + '/sitemap.xml\n' : 'Disallow: /\n'));
console.log(ready ? 'Public pages prepared. Search Console verification and sitemap submission are still owner actions.' : 'Preview build: search indexing disabled. Set validated launch configuration when ready.');
