import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  MAX_BODY_BYTES,
  buildHarEntry,
  buildHarLog,
  chromiumExtensionIdFromKey,
  detectBrowser,
  extractRequestBody,
  normalizeDaemonUrl,
  shouldCapture,
  truncateUtf8,
} from '../lib/har-capture.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const extRoot = path.resolve(here, '..');
const repoRoot = path.resolve(extRoot, '..');

// The same kind of sample data https://dlptest.com/http-post/ provides.
const TEST_CARD = '4532015112830366'; // Luhn-valid Visa test number
const TEST_SSN = '123-45-6789';

test('formData bodies become HAR params plus urlencoded text', () => {
  const body = extractRequestBody({
    formData: { name: ['Jane Doe'], ssn: [TEST_SSN], card: [TEST_CARD], tags: ['a', 'b'] },
  });
  assert.equal(body.mimeType, 'application/x-www-form-urlencoded');
  assert.deepEqual(body.params, [
    { name: 'name', value: 'Jane Doe' },
    { name: 'ssn', value: TEST_SSN },
    { name: 'card', value: TEST_CARD },
    { name: 'tags', value: 'a' },
    { name: 'tags', value: 'b' },
  ]);
  const roundTrip = new URLSearchParams(body.text);
  assert.equal(roundTrip.get('ssn'), TEST_SSN);
  assert.equal(roundTrip.get('card'), TEST_CARD);
  assert.deepEqual(roundTrip.getAll('tags'), ['a', 'b']);
  assert.equal(body.truncated, false);
  assert.equal(body.error, null);
});

test('raw byte bodies are UTF-8 decoded across chunk boundaries', () => {
  const json = JSON.stringify({ customer: 'Zoë Ålänď', ssn: TEST_SSN, card: TEST_CARD, note: '日本語 ✓' });
  const bytes = new TextEncoder().encode(json);
  // Split inside a multi-byte sequence to prove chunks are concatenated before decoding.
  const split = bytes.indexOf(0xc3) + 1;
  const body = extractRequestBody({
    raw: [{ bytes: bytes.slice(0, split).buffer }, { bytes: bytes.slice(split).buffer }],
  });
  assert.equal(body.text, json);
  assert.equal(body.mimeType, 'application/json');
  assert.equal(body.bodySize, bytes.byteLength);
  assert.equal(body.truncated, false);
});

test('raw file parts are noted without reading the file', () => {
  const body = extractRequestBody({ raw: [{ file: 'C:\\Users\\me\\payroll.xlsx' }] });
  assert.match(body.text, /\[file upload: C:\\Users\\me\\payroll\.xlsx\]/);
});

test('urlencoded raw text is classified as form data', () => {
  const text = `ssn=${TEST_SSN}&card=${TEST_CARD}`;
  const body = extractRequestBody({ raw: [{ bytes: new TextEncoder().encode(text).buffer }] });
  assert.equal(body.mimeType, 'application/x-www-form-urlencoded');
  assert.equal(body.text, text);
});

test('raw bodies are capped at the byte limit without splitting code points', () => {
  const big = 'é'.repeat(MAX_BODY_BYTES); // 2 bytes each → 2x the cap
  const bytes = new TextEncoder().encode(big);
  const body = extractRequestBody({ raw: [{ bytes: bytes.buffer }] });
  assert.equal(body.truncated, true);
  assert.equal(body.bodySize, bytes.byteLength);
  const keptBytes = new TextEncoder().encode(body.text).byteLength;
  assert.ok(keptBytes <= MAX_BODY_BYTES, `kept ${keptBytes} > cap`);
  assert.ok(keptBytes >= MAX_BODY_BYTES - 2, 'should keep almost the full cap');
  assert.ok(!body.text.includes('\uFFFD'), 'no replacement characters from a split sequence');
});

test('custom smaller cap is honoured for formData', () => {
  const body = extractRequestBody({ formData: { blob: ['x'.repeat(5000)], ssn: [TEST_SSN] } }, { maxBytes: 1024 });
  assert.equal(body.truncated, true);
  assert.ok(new TextEncoder().encode(body.text).byteLength <= 1024);
  assert.ok(body.bodySize > 5000);
});

test('truncateUtf8 cuts on code point boundaries', () => {
  assert.deepEqual(truncateUtf8('abc', 10), { text: 'abc', truncated: false });
  const cut = truncateUtf8('aé', 2); // 'a' (1) + 'é' (2) → only 'a' fits
  assert.deepEqual(cut, { text: 'a', truncated: true });
});

test('requestBody errors are surfaced, not thrown', () => {
  const body = extractRequestBody({ error: 'Unknown error.' });
  assert.equal(body.error, 'Unknown error.');
  assert.equal(body.text, '');
});

test('shouldCapture filters methods, loopback daemon traffic and extension-initiated requests', () => {
  const base = { url: 'https://dlptest.com/http-post/', method: 'POST', requestBody: { formData: { a: ['1'] } } };
  assert.equal(shouldCapture(base), true);
  assert.equal(shouldCapture({ ...base, method: 'put' }), true);
  assert.equal(shouldCapture({ ...base, method: 'PATCH' }), true);
  assert.equal(shouldCapture({ ...base, method: 'GET' }), false);
  assert.equal(shouldCapture({ ...base, url: 'http://127.0.0.1:3030/api/browser-sensor/har' }), false);
  assert.equal(shouldCapture({ ...base, url: 'http://localhost:3030/x' }), false);
  assert.equal(shouldCapture({ ...base, initiator: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop' }), false);
  assert.equal(shouldCapture({ ...base, originUrl: 'moz-extension://1234/background.html' }), false);
  assert.equal(shouldCapture({ ...base, url: 'ftp://example.com/' }), false);
  assert.equal(shouldCapture({ ...base, requestBody: undefined }), false);
});

test('daemon URL must be loopback', () => {
  assert.equal(normalizeDaemonUrl('http://127.0.0.1:3030/'), 'http://127.0.0.1:3030');
  assert.equal(normalizeDaemonUrl('http://localhost:4040'), 'http://localhost:4040');
  assert.throws(() => normalizeDaemonUrl('https://evil.example.com'), /loopback/);
  assert.throws(() => normalizeDaemonUrl('file:///etc/passwd'), /http/);
});

test('buildHarEntry produces a HAR 1.2 request with postData for the daemon pipeline', () => {
  const details = {
    requestId: '42',
    url: 'https://dlptest.com/http-post/?src=form',
    method: 'POST',
    timeStamp: Date.UTC(2026, 9, 24, 6, 0, 0),
    tabId: 7,
    type: 'main_frame',
    initiator: 'https://dlptest.com',
  };
  const body = extractRequestBody({ formData: { ssn: [TEST_SSN], card: [TEST_CARD] } });
  const browser = detectBrowser({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70' });
  const entry = buildHarEntry(details, body, { browser });
  assert.equal(entry.startedDateTime, '2026-10-24T06:00:00.000Z');
  assert.equal(entry.request.method, 'POST');
  assert.equal(entry.request.url, details.url);
  assert.deepEqual(entry.request.queryString, [{ name: 'src', value: 'form' }]);
  assert.equal(entry.request.postData.mimeType, 'application/x-www-form-urlencoded');
  assert.ok(entry.request.postData.text.includes(TEST_CARD));
  assert.deepEqual(entry.request.postData.params.map((p) => p.name), ['ssn', 'card']);
  assert.equal(entry._oshoosi.browser, 'msedge.exe');
  const log = buildHarLog([entry], browser);
  assert.equal(log.log.version, '1.2');
  assert.equal(log.log.browser.name, 'msedge.exe');
  assert.equal(log.log.entries.length, 1);
});

test('detectBrowser maps user agents to EDR actor image names', () => {
  assert.equal(detectBrowser({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0' }).name, 'firefox.exe');
  assert.equal(detectBrowser({ userAgent: 'Mozilla/5.0 AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36' }).name, 'chrome.exe');
  assert.equal(detectBrowser({ userAgentData: { brands: [{ brand: 'Brave', version: '131' }] }, userAgent: 'Chrome/131.0.0.0' }).name, 'brave.exe');
});

test('manifest key, extension ID and daemon allowlist stay in sync', async () => {
  const manifest = JSON.parse(readFileSync(path.join(extRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.permissions.includes('webRequest'));
  const sha256 = async (bytes) => webcrypto.subtle.digest('SHA-256', bytes);
  const id = await chromiumExtensionIdFromKey(manifest.key, sha256);
  // Cross-check against an independent computation with node:crypto.
  const der = Buffer.from(manifest.key, 'base64');
  const hex = createHash('sha256').update(der).digest('hex').slice(0, 32);
  const expected = [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join('');
  assert.equal(id, expected);
  const rustSrc = readFileSync(path.join(repoRoot, 'crates', 'osoosi-dashboard', 'src', 'routes', 'browser_sensor.rs'), 'utf8');
  const m = rustSrc.match(/pub const DEFAULT_SENSOR_EXTENSION_ID: &str = "([a-p]{32})";/);
  assert.ok(m, 'DEFAULT_SENSOR_EXTENSION_ID constant not found in browser_sensor.rs');
  assert.equal(m[1], id, 'daemon allowlisted extension ID must match manifest key');
});
