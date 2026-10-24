// OshoosiClaw Browser DLP Sensor — MV3 background service worker (Chromium) / event page (Firefox).
//
// Observes outgoing POST/PUT/PATCH request bodies with webRequest.onBeforeRequest(requestBody),
// converts them into HAR 1.2 entries, and streams them ONLY to the local OshoosiClaw daemon
// (loopback). The daemon feeds them through the same HAR → Two-Tier DLP pipeline used for
// browser-exported .har files and the HAR import endpoint.
//
// Service workers are ephemeral: all state lives in chrome.storage (never in globals).

import {
  MAX_BODY_BYTES,
  SENSOR_VERSION,
  buildHarEntry,
  buildHarLog,
  detectBrowser,
  extractRequestBody,
  normalizeDaemonUrl,
  shouldCapture,
} from './lib/har-capture.js';

const DEFAULT_DAEMON_URL = 'http://127.0.0.1:3030';
const PAIR_PATH = '/api/browser-sensor/pair';
const INGEST_PATH = '/api/browser-sensor/har';
const MAX_PENDING_ENTRIES = 200;
const MAX_BATCH_ENTRIES = 25;
const FLUSH_DEBOUNCE_MS = 300;
const RETRY_ALARM = 'oshoosi-dlp-flush-retry';

const browserInfo = detectBrowser(globalThis.navigator);

// Serialises read-modify-write cycles on chrome.storage.session within one worker lifetime.
let storageChain = Promise.resolve();
function withStorageLock(fn) {
  const run = storageChain.then(fn, fn);
  storageChain = run.catch(() => {});
  return run;
}

async function getDaemonUrl() {
  const { daemonUrl } = await chrome.storage.local.get('daemonUrl');
  try {
    return normalizeDaemonUrl(daemonUrl || DEFAULT_DAEMON_URL);
  } catch {
    return DEFAULT_DAEMON_URL;
  }
}

async function bumpStat(field, delta = 1, extra = {}) {
  const { stats = {} } = await chrome.storage.local.get('stats');
  stats[field] = (stats[field] || 0) + delta;
  Object.assign(stats, extra);
  await chrome.storage.local.set({ stats });
  return stats;
}

async function setBadge(stats) {
  try {
    const detections = stats.detections || 0;
    if (stats.paired === false) {
      await chrome.action.setBadgeText({ text: '!' });
      await chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    } else if (detections > 0) {
      await chrome.action.setBadgeText({ text: detections > 99 ? '99+' : String(detections) });
      await chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
    } else {
      await chrome.action.setBadgeText({ text: '' });
    }
  } catch (err) {
    console.warn('[OshoosiClaw DLP] badge update failed', err);
  }
}

/** Zero-touch pairing: the daemon issues a sensor token bound to this extension's origin. */
async function pairWithDaemon() {
  const base = await getDaemonUrl();
  const res = await fetch(`${base}${PAIR_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sensor_version: SENSOR_VERSION, browser: browserInfo }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => '');
    const stats = await bumpStat('pairFailures', 1, { paired: false, lastError: `pair HTTP ${res.status} ${detail.slice(0, 200)}` });
    await setBadge(stats);
    throw new Error(`pairing rejected: HTTP ${res.status}`);
  }
  const data = await res.json();
  if (!data || typeof data.token !== 'string' || data.token.length < 32) {
    throw new Error('pairing response missing token');
  }
  await chrome.storage.local.set({ sensorToken: data.token, pairedAt: new Date().toISOString() });
  const stats = await bumpStat('pairings', 1, { paired: true, lastError: null });
  await setBadge(stats);
  return data.token;
}

async function getSensorToken() {
  const { sensorToken } = await chrome.storage.local.get('sensorToken');
  if (typeof sensorToken === 'string' && sensorToken.length >= 32) return sensorToken;
  return pairWithDaemon();
}

async function enqueue(entry) {
  await withStorageLock(async () => {
    const { pending = [] } = await chrome.storage.session.get('pending');
    pending.push(entry);
    let dropped = 0;
    while (pending.length > MAX_PENDING_ENTRIES) {
      pending.shift();
      dropped += 1;
    }
    await chrome.storage.session.set({ pending });
    if (dropped > 0) await bumpStat('dropped', dropped);
  });
}

async function postBatch(entries, token) {
  const base = await getDaemonUrl();
  return fetch(`${base}${INGEST_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Osoosi-Sensor-Token': token },
    body: JSON.stringify(buildHarLog(entries, browserInfo)),
  });
}

async function recordVerdicts(payload) {
  const verdicts = Array.isArray(payload && payload.verdicts) ? payload.verdicts : [];
  const blocked = verdicts.filter((v) => v && v.allowed === false);
  if (blocked.length === 0) return;
  const last = blocked[blocked.length - 1];
  const stats = await bumpStat('detections', blocked.length, {
    lastDetection: {
      at: new Date().toISOString(),
      url: String(last.destination_sink || ''),
      categories: Array.isArray(last.detected_categories) ? last.detected_categories.slice(0, 12) : [],
      decision: String(last.dlp_response || last.authorization_decision || 'DENY'),
    },
  });
  await setBadge(stats);
}

let flushTimer = null;
function scheduleFlush() {
  if (flushTimer !== null) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flush().catch((err) => console.warn('[OshoosiClaw DLP] flush failed', err));
  }, FLUSH_DEBOUNCE_MS);
}

async function flush() {
  const batch = await withStorageLock(async () => {
    const { pending = [] } = await chrome.storage.session.get('pending');
    return pending.slice(0, MAX_BATCH_ENTRIES);
  });
  if (batch.length === 0) return;

  let token;
  try {
    token = await getSensorToken();
  } catch (err) {
    await chrome.alarms.create(RETRY_ALARM, { delayInMinutes: 1 });
    throw err;
  }

  let res;
  try {
    res = await postBatch(batch, token);
    if (res.status === 401 || res.status === 403) {
      // Token rotated (dashboard token changed) or origin re-keyed: re-pair once and retry.
      await chrome.storage.local.remove('sensorToken');
      token = await pairWithDaemon();
      res = await postBatch(batch, token);
    }
  } catch (err) {
    const stats = await bumpStat('deliveryFailures', 1, { lastError: `daemon unreachable: ${String(err && err.message ? err.message : err)}` });
    await setBadge(stats);
    await chrome.alarms.create(RETRY_ALARM, { delayInMinutes: 1 });
    return;
  }

  if (!res.ok) {
    await bumpStat('deliveryFailures', 1, { lastError: `ingest HTTP ${res.status}` });
    await chrome.alarms.create(RETRY_ALARM, { delayInMinutes: 1 });
    return;
  }

  const sentIds = new Set(batch.map((e) => e._oshoosi && e._oshoosi.captureId));
  await withStorageLock(async () => {
    const { pending = [] } = await chrome.storage.session.get('pending');
    const remaining = pending.filter((e) => !sentIds.has(e._oshoosi && e._oshoosi.captureId));
    await chrome.storage.session.set({ pending: remaining });
  });
  await bumpStat('forwarded', batch.length, { lastForwardAt: new Date().toISOString(), lastError: null });
  const payload = await res.json().catch(() => null);
  await recordVerdicts(payload);

  const { pending: rest = [] } = await chrome.storage.session.get('pending');
  if (rest.length > 0) scheduleFlush();
}

async function handleRequest(details) {
  if (!shouldCapture(details)) return;
  const body = extractRequestBody(details.requestBody, { maxBytes: MAX_BODY_BYTES });
  if (!body.text && body.params.length === 0) return;
  const entry = buildHarEntry(details, body, { browser: browserInfo });
  entry._oshoosi.captureId = `${details.requestId}-${details.timeStamp}-${crypto.randomUUID()}`;
  await enqueue(entry);
  scheduleFlush();
}

// Listeners must be registered synchronously at the top level so the worker is woken for them.
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    handleRequest(details).catch((err) => console.warn('[OshoosiClaw DLP] capture failed', err));
  },
  { urls: ['http://*/*', 'https://*/*'] },
  ['requestBody'],
);

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RETRY_ALARM) {
    flush().catch((err) => console.warn('[OshoosiClaw DLP] retry flush failed', err));
  }
});

chrome.runtime.onInstalled.addListener(() => {
  pairWithDaemon().catch((err) => console.warn('[OshoosiClaw DLP] initial pairing failed; will retry on first capture', err));
});

chrome.runtime.onStartup.addListener(() => {
  getSensorToken().catch((err) => console.warn('[OshoosiClaw DLP] startup pairing failed', err));
});

chrome.action.onClicked.addListener(async () => {
  await chrome.runtime.openOptionsPage();
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (!message || typeof message.type !== 'string') {
      sendResponse({ ok: false, error: 'invalid message' });
      return;
    }
    if (message.type === 'status') {
      const local = await chrome.storage.local.get(['stats', 'pairedAt', 'daemonUrl']);
      const { pending = [] } = await chrome.storage.session.get('pending');
      sendResponse({ ok: true, browser: browserInfo, daemonUrl: await getDaemonUrl(), pending: pending.length, ...local });
    } else if (message.type === 'repair') {
      await chrome.storage.local.remove('sensorToken');
      try {
        await pairWithDaemon();
        sendResponse({ ok: true });
      } catch (err) {
        sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
      }
    } else if (message.type === 'setDaemonUrl') {
      try {
        const origin = normalizeDaemonUrl(String(message.daemonUrl || ''));
        await chrome.storage.local.set({ daemonUrl: origin });
        await chrome.storage.local.remove('sensorToken');
        sendResponse({ ok: true, daemonUrl: origin });
      } catch (err) {
        sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
      }
    } else if (message.type === 'resetDetections') {
      const stats = await bumpStat('detections', 0, { detections: 0, lastDetection: null });
      await setBadge(stats);
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: `unknown message type ${message.type}` });
    }
  })();
  return true;
});
