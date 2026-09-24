// UI checks use synthetic accounts and stubbed responses; they do not verify Supabase.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import AxeBuilder from '@axe-core/playwright';

const base = 'http://127.0.0.1:5179';
const api = 'https://api.example.test';
const auth = 'https://test-project.supabase.co';
const server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '5179', '--strictPort'], {
  cwd: process.cwd(), stdio: 'pipe', env: { ...process.env, VITE_API_URL: api, VITE_SUPABASE_URL: auth, VITE_SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_synthetic_browser_test' },
});
let browser;
const consoleErrors = [];
const caseId = 42;
const user = { id: '00000000-0000-0000-0000-000000000001', email: 'synthetic@example.test', email_confirmed_at: '2026-01-01T00:00:00Z', role: 'authenticated', aud: 'authenticated', app_metadata: {}, user_metadata: {} };
const result = { id: caseId, investigation_id: caseId, input_type: 'text', content: 'Synthetic suspicious message', threat_score: 45, verdict: 'Suspicious', confidence: 60, reasoning: 'Synthetic evidence for browser tests.', insufficient_evidence: true, evidence_items: [], attack_findings: [{ attack_type: 'Credential phishing', category: 'Social engineering', severity: 'Medium', confidence: 60, evidence_ids: [], limitations: [] }], attack_chain: [], url_analysis: [], threat_intelligence: [], persistence: { status: 'saved' } };
let removed = false, failDelete = false, analysisStatus = 200, historyStatus = 200, pendingAnalysis;
const requests = [];
const output = process.env.UI_SCREENSHOT_DIR || 'test-results';
async function audit(page, name) {
  const scan = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  assert.deepEqual(scan.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })), [], 'Accessibility: ' + name);
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Horizontal overflow: ' + name);
}
try {
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(base)).ok) break; } catch { /* Wait for local server. */ }
    if (i === 59) throw new Error('Vite did not become ready');
    await delay(150);
  }
  browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, reducedMotion: 'reduce' });
  await context.route(auth + '/**', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(user) }));
  await context.route(api + '/**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    requests.push(request.method() + ' ' + url.pathname + url.search);
    let status = 200, data;
    if (url.pathname === '/investigations' && request.method() === 'GET') { status = historyStatus; data = removed ? [] : [{ id: caseId, input_type: 'text', content_preview: 'Synthetic suspicious message', verdict: 'Suspicious', threat_score: 45 }]; }
    else if (request.method() === 'DELETE') { status = failDelete ? 503 : 200; if (!failDelete) removed = true; data = { status: 'deleted' }; }
    else if (url.pathname === '/investigate') { if (pendingAnalysis) await pendingAnalysis; status = analysisStatus; data = result; }
    else data = result;
    if (status !== 200) data = { detail: ({ 401: 'Your session expired. Please sign in again.', 403: 'Confirm your email before investigating.', 429: 'Daily limit reached.', 503: 'History is temporarily unavailable.' })[status] };
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
  });
  const page = await context.newPage();
  page.on('pageerror', error => consoleErrors.push(error.message));
  await mkdir(output, { recursive: true });
  await page.goto(base);
  await page.getByRole('heading', { level: 1 }).waitFor();
  await audit(page, 'desktop overview');
  await page.screenshot({ path: output + '/desktop-light.png', fullPage: true });
  await page.getByRole('switch', { name: 'Dark mode' }).click();
  await audit(page, 'dark overview');
  await page.screenshot({ path: output + '/desktop-dark.png', fullPage: true });
  await page.getByRole('switch', { name: 'Dark mode' }).click();
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('dialog').waitFor();
  await audit(page, 'account dialog');
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('button', { name: 'Sign in', exact: true }).evaluate(el => el === document.activeElement), true);
  await page.setViewportSize({ width: 390, height: 844 });
  await audit(page, 'mobile overview');
  await page.screenshot({ path: output + '/mobile-light.png', fullPage: true });
  await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await page.getByRole('link', { name: 'Already affected?', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: 'Menu', exact: true }).getAttribute('aria-expanded'), 'false');
  await audit(page, 'mobile recovery');
  await page.setViewportSize({ width: 320, height: 740 });
  await audit(page, '320px recovery');
  await page.goto(base + '/#investigate/file');
  await audit(page, '320px file form');
  await page.getByLabel('Browse files').setInputFiles({ name: 'bad.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('synthetic') });
  await page.getByText('Choose one of the supported file types listed below.').waitFor();
  await context.setOffline(true);
  await page.getByText('You’re offline', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Reconnect to investigate' }).isDisabled(), true);
  await context.setOffline(false);
  // Inject a synthetic session only into this browser context.
  await page.evaluate(user => {
    const expiry = Math.floor(Date.now() / 1000) + 3600;
    const token = btoa(JSON.stringify({ alg: 'HS256' })) + '.' + btoa(JSON.stringify({ sub: user.id, exp: expiry, role: 'authenticated' })) + '.synthetic';
    localStorage.setItem('sb-test-project-auth-token', JSON.stringify({ access_token: token, refresh_token: 'synthetic', expires_at: expiry, expires_in: 3600, token_type: 'bearer', user }));
  }, user);
  await page.reload();
  await page.getByRole('button', { name: 'My account', exact: true }).waitFor();
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.goto(base + '/#history');
  await page.getByText('Synthetic suspicious message', { exact: true }).waitFor();
  assert(requests.includes('GET /investigations?summary=true'));
  await page.getByRole('searchbox').fill('nonexistent');
  await page.getByRole('heading', { name: 'No matching investigations' }).waitFor();
  await page.getByRole('button', { name: 'Clear search' }).click();
  await page.getByRole('button', { name: /CASE #42/ }).click();
  await page.getByRole('button', { name: 'What to do next', exact: true }).waitFor();
  assert(requests.includes('GET /investigations/42'));
  await audit(page, 'results');
  await page.screenshot({ path: output + '/results.png', fullPage: true });
  await page.getByRole('button', { name: 'What to do next', exact: true }).click();
  await page.getByRole('combobox').selectOption('payment');
  await page.getByText(/Contact your bank or payment provider immediately/).waitFor();
  await page.goto(base + '/#history');
  await page.getByRole('button', { name: 'Delete investigation 42' }).click();
  failDelete = true;
  await page.getByRole('button', { name: 'Delete permanently', exact: true }).click();
  await page.getByText('History is temporarily unavailable.', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Delete investigation 42' }).isVisible(), true);
  failDelete = false;
  await page.getByRole('button', { name: 'Delete investigation 42' }).click();
  await page.getByRole('button', { name: 'Delete permanently', exact: true }).click();
  await page.getByText('Investigation permanently deleted from active storage.').waitFor();
  await page.getByRole('heading', { name: 'A fresh start.' }).waitFor();
  await page.goto(base + '/#investigate/message');
  await page.getByLabel('Message content').fill('Synthetic test');
  await page.getByRole('checkbox').check();
  analysisStatus = 403;
  await page.getByRole('button', { name: 'Investigate evidence', exact: true }).click();
  await page.getByText('Permission denied', { exact: true }).waitFor();
  analysisStatus = 429;
  await page.getByRole('button', { name: 'Investigate evidence', exact: true }).click();
  await page.getByText('Request limit reached', { exact: true }).waitFor();
  analysisStatus = 200;
  let release;
  pendingAnalysis = new Promise(resolve => { release = resolve; });
  await page.clock.install();
  await page.getByRole('button', { name: 'Investigate evidence', exact: true }).click();
  await page.getByText('Examining the evidence…', { exact: true }).waitFor();
  assert.equal(await page.locator('.spinning-shield').evaluate(el => getComputedStyle(el).animationName), 'none');
  await page.clock.fastForward(16000);
  await page.getByText('This is taking a little longer', { exact: true }).waitFor();
  release(); pendingAnalysis = null;
  await page.getByRole('button', { name: 'What to do next', exact: true }).waitFor();
  historyStatus = 401;
  await page.goto(base + '/#history');
  await page.getByRole('dialog').waitFor();
  await page.getByText('Your session expired. Please sign in again.', { exact: true }).waitFor();
  assert.deepEqual(consoleErrors, []);
  console.log('PASS: responsive layouts, light/dark, automated WCAG checks, dialog focus, offline, validation, automatic summary history, full-case fetch, empty/search, deletion failure/success, denied/limited/expired, loading/slow and reduced motion. Auth and API responses were mocked.');
} finally {
  await browser?.close();
  server.kill('SIGTERM');
}
