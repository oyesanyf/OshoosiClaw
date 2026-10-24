// OshoosiClaw Browser DLP Sensor — pure request-body → HAR 1.2 conversion helpers.
//
// This module has no dependency on the `chrome.*` / `browser.*` APIs so it can be unit-tested
// with `node --test` and shared by the MV3 service worker (Chromium) and the Firefox event page.

/** Hard cap (bytes) on the request body text forwarded to the local daemon per request. */
export const MAX_BODY_BYTES = 256 * 1024;

/** HTTP methods whose bodies are inspected for data-loss prevention. */
export const CAPTURED_METHODS = new Set(['POST', 'PUT', 'PATCH']);

/** Hostnames that identify the local OshoosiClaw daemon (never captured, never a sink). */
export const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

export const SENSOR_NAME = 'OshoosiClaw Browser DLP Sensor';
export const SENSOR_VERSION = '1.2.0';

const utf8Encoder = new TextEncoder();

/** Returns the UTF-8 byte length of a string. */
export function utf8ByteLength(text) {
  return utf8Encoder.encode(text).byteLength;
}

/**
 * Truncates `text` so that its UTF-8 encoding is at most `maxBytes` bytes without splitting a
 * multi-byte code point. Returns `{ text, truncated }`.
 */
export function truncateUtf8(text, maxBytes) {
  const encoded = utf8Encoder.encode(text);
  if (encoded.byteLength <= maxBytes) {
    return { text, truncated: false };
  }
  let end = Math.max(0, maxBytes);
  // Walk back over UTF-8 continuation bytes (10xxxxxx) so we cut on a code-point boundary.
  while (end > 0 && (encoded[end] & 0xc0) === 0x80) {
    end -= 1;
  }
  const decoder = new TextDecoder('utf-8', { fatal: false });
  return { text: decoder.decode(encoded.subarray(0, end)), truncated: true };
}

/**
 * Returns true when `rawUrl` points at a loopback host (the local daemon or any local service).
 * Loopback traffic never leaves the machine, so it is not an exfiltration sink.
 */
export function isLoopbackUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return LOOPBACK_HOSTS.has(u.hostname) || u.hostname.endsWith('.localhost');
  } catch {
    return false;
  }
}

/**
 * Validates a daemon base URL. Only loopback http(s) origins are accepted so captured data can
 * never be forwarded anywhere except the local OshoosiClaw agent.
 */
export function normalizeDaemonUrl(rawUrl) {
  const u = new URL(rawUrl);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error(`Daemon URL must be http(s): ${rawUrl}`);
  }
  if (!LOOPBACK_HOSTS.has(u.hostname)) {
    throw new Error(`Daemon URL must be a loopback address (127.0.0.1 / localhost / [::1]): ${rawUrl}`);
  }
  return u.origin;
}

/**
 * Decides whether a `webRequest.onBeforeRequest` event should be captured.
 * @param {object} details webRequest details (method, url, initiator/originUrl, requestBody).
 */
export function shouldCapture(details) {
  if (!details || typeof details.url !== 'string') return false;
  const method = String(details.method || '').toUpperCase();
  if (!CAPTURED_METHODS.has(method)) return false;
  if (!/^https?:\/\//i.test(details.url)) return false;
  if (isLoopbackUrl(details.url)) return false;
  const initiator = String(details.initiator || details.originUrl || '');
  if (initiator.startsWith('chrome-extension://') || initiator.startsWith('moz-extension://')) {
    return false;
  }
  return Boolean(details.requestBody);
}

function guessMimeType(text) {
  const trimmed = text.trim();
  if (trimmed.length === 0) return 'application/octet-stream';
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      JSON.parse(trimmed);
      return 'application/json';
    } catch {
      /* fall through */
    }
  }
  if (/^[^\s=&]+=[^&]*(&[^\s=&]+=[^&]*)*$/.test(trimmed)) {
    return 'application/x-www-form-urlencoded';
  }
  return 'text/plain';
}

function concatChunks(chunks, totalLength) {
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}

function toUint8Array(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return null;
}

/**
 * Converts a webRequest `requestBody` object into HAR `postData` fields.
 *
 * - `formData` (parsed urlencoded or multipart fields) → `params` + urlencoded `text`.
 * - `raw` (array of `{ bytes: ArrayBuffer }` / `{ file: string }`) → UTF-8 decoded `text`.
 *
 * The forwarded text is capped at `maxBytes` UTF-8 bytes; `bodySize` reports the original size.
 *
 * @returns {{ mimeType: string, text: string, params: Array<{name: string, value: string}>,
 *             bodySize: number, truncated: boolean, error: string|null }}
 */
export function extractRequestBody(requestBody, { maxBytes = MAX_BODY_BYTES } = {}) {
  const result = { mimeType: 'application/octet-stream', text: '', params: [], bodySize: 0, truncated: false, error: null };
  if (!requestBody) return result;
  if (requestBody.error) {
    result.error = String(requestBody.error);
    return result;
  }

  if (requestBody.formData && typeof requestBody.formData === 'object') {
    const search = new URLSearchParams();
    let budget = maxBytes;
    for (const [name, values] of Object.entries(requestBody.formData)) {
      for (const rawValue of Array.isArray(values) ? values : [values]) {
        const value = String(rawValue ?? '');
        const pairBytes = utf8ByteLength(name) + utf8ByteLength(value) + 2;
        result.bodySize += pairBytes;
        if (budget <= 0) {
          result.truncated = true;
          continue;
        }
        const cut = truncateUtf8(value, Math.max(0, budget - utf8ByteLength(name) - 2));
        if (cut.truncated) result.truncated = true;
        result.params.push({ name, value: cut.text });
        search.append(name, cut.text);
        budget -= utf8ByteLength(name) + utf8ByteLength(cut.text) + 2;
      }
    }
    const encoded = truncateUtf8(search.toString(), maxBytes);
    if (encoded.truncated) result.truncated = true;
    result.text = encoded.text;
    result.mimeType = 'application/x-www-form-urlencoded';
    return result;
  }

  if (Array.isArray(requestBody.raw)) {
    const chunks = [];
    let kept = 0;
    const fileNotes = [];
    for (const part of requestBody.raw) {
      if (part && part.file) {
        fileNotes.push(`[file upload: ${String(part.file)}]`);
        continue;
      }
      const bytes = toUint8Array(part && part.bytes);
      if (!bytes) continue;
      result.bodySize += bytes.byteLength;
      if (kept >= maxBytes) {
        result.truncated = true;
        continue;
      }
      const room = maxBytes - kept;
      const slice = bytes.byteLength > room ? bytes.subarray(0, room) : bytes;
      if (slice.byteLength < bytes.byteLength) result.truncated = true;
      chunks.push(slice);
      kept += slice.byteLength;
    }
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let text = decoder.decode(concatChunks(chunks, kept));
    if (result.truncated) {
      // Drop a trailing replacement char produced by cutting a multi-byte sequence.
      text = text.replace(/\uFFFD$/, '');
    }
    if (fileNotes.length > 0) {
      text = text ? `${text}\n${fileNotes.join('\n')}` : fileNotes.join('\n');
    }
    result.text = text;
    result.mimeType = guessMimeType(text);
    return result;
  }

  return result;
}

/**
 * Identifies the host browser from `navigator.userAgentData` / `navigator.userAgent` and maps it
 * to the process image name the EDR uses as the DLP actor.
 */
export function detectBrowser(nav) {
  const brands = (nav && nav.userAgentData && Array.isArray(nav.userAgentData.brands)) ? nav.userAgentData.brands : [];
  const ua = String((nav && nav.userAgent) || '');
  const brandNames = brands.map((b) => String(b.brand || ''));
  const pick = (re) => {
    const m = ua.match(re);
    return m ? m[1] : '';
  };
  if (brandNames.some((b) => /Microsoft Edge/i.test(b)) || /\bEdg\//.test(ua)) {
    return { name: 'msedge.exe', version: pick(/Edg\/([\d.]+)/) };
  }
  if (brandNames.some((b) => /Brave/i.test(b))) {
    return { name: 'brave.exe', version: pick(/Chrome\/([\d.]+)/) };
  }
  if (/Firefox\//.test(ua)) {
    return { name: 'firefox.exe', version: pick(/Firefox\/([\d.]+)/) };
  }
  if (brandNames.some((b) => /Opera/i.test(b)) || /\bOPR\//.test(ua)) {
    return { name: 'opera.exe', version: pick(/OPR\/([\d.]+)/) };
  }
  if (brandNames.some((b) => /Google Chrome|Chromium/i.test(b)) || /Chrome\//.test(ua)) {
    return { name: 'chrome.exe', version: pick(/Chrome\/([\d.]+)/) };
  }
  return { name: 'browser', version: '' };
}

/**
 * Builds one W3C HAR 1.2 entry (request side only — the response has not happened yet when the
 * request body is observed) carrying `request.postData` for the daemon's HAR→DLP pipeline.
 */
export function buildHarEntry(details, body, { browser } = {}) {
  let queryString = [];
  try {
    const u = new URL(details.url);
    queryString = [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch {
    queryString = [];
  }
  const started = typeof details.timeStamp === 'number' ? new Date(details.timeStamp) : new Date();
  const postData = { mimeType: body.mimeType, text: body.text };
  if (body.params && body.params.length > 0) {
    postData.params = body.params.map((p) => ({ name: p.name, value: p.value }));
  }
  return {
    startedDateTime: started.toISOString(),
    time: 0,
    request: {
      method: String(details.method || 'POST').toUpperCase(),
      url: details.url,
      httpVersion: 'HTTP/1.1',
      cookies: [],
      headers: [],
      queryString,
      postData,
      headersSize: -1,
      bodySize: body.bodySize,
    },
    response: {
      status: 0,
      statusText: '',
      httpVersion: 'HTTP/1.1',
      cookies: [],
      headers: [],
      content: { size: 0, mimeType: 'x-unknown' },
      redirectURL: '',
      headersSize: -1,
      bodySize: -1,
    },
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
    _oshoosi: {
      requestId: String(details.requestId ?? ''),
      tabId: typeof details.tabId === 'number' ? details.tabId : -1,
      type: String(details.type || ''),
      initiator: String(details.initiator || details.originUrl || details.documentUrl || ''),
      browser: browser ? browser.name : 'browser',
      truncated: Boolean(body.truncated),
    },
  };
}

/** Wraps HAR entries into a HAR 1.2 log document. */
export function buildHarLog(entries, browser) {
  return {
    log: {
      version: '1.2',
      creator: { name: SENSOR_NAME, version: SENSOR_VERSION },
      browser: { name: browser ? browser.name : 'browser', version: browser ? browser.version : '' },
      entries,
    },
  };
}

/**
 * Computes the Chromium extension ID for a base64 SubjectPublicKeyInfo `key` (manifest "key").
 * Chromium IDs are the first 128 bits of SHA-256(DER) rendered with the alphabet a–p.
 * `sha256` must be an async function returning an ArrayBuffer/Uint8Array digest.
 */
export async function chromiumExtensionIdFromKey(base64Key, sha256) {
  const der = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await sha256(der));
  let id = '';
  for (let i = 0; i < 16; i += 1) {
    id += String.fromCharCode(97 + (digest[i] >> 4));
    id += String.fromCharCode(97 + (digest[i] & 0x0f));
  }
  return id;
}
