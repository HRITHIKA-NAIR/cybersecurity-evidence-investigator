import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validatePublicConfig } from '../scripts/public-config.mjs';

test('public keys and local development origins are allowed', () => {
  validatePublicConfig({ VITE_SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_synthetic', VITE_API_URL: 'http://127.0.0.1:8001' });
});
test('unknown VITE variables cannot silently enter a browser bundle', () => {
  assert.throws(() => validatePublicConfig({ VITE_NEW_TOKEN: 'synthetic' }), /Unapproved/);
});
test('Supabase secret and privileged JWT keys are rejected', () => {
  const payload = Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url');
  for (const key of ['sb_secret_synthetic', `eyJtest.${payload}.signature`, 'not-a-public-key']) {
    assert.throws(() => validatePublicConfig({ VITE_SUPABASE_PUBLISHABLE_KEY: key }), /forbidden/);
  }
});
test('credential-bearing and non-HTTPS public URLs are rejected without logging credentials', () => {
  for (const url of ['https://user:private@example.com', 'https://example.com/?token=private', 'http://example.com', 'https://example.com/auth']) {
    assert.throws(() => validatePublicConfig({ VITE_API_URL: url }), error => !error.message.includes('private'));
  }
});
