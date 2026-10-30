/**
 * dashboard/tests/m6_challenger_canvas_stress.test.mjs
 *
 * Milestone M6 Empirical Challenger Canvas & Steganography Stress Test Suite
 * Features F36 (Defense Code Accordion & Zero-String Ephemeral Canvas)
 * and F37 (HTML5 Canvas RGB LSB Steganography & AES-GCM Hardening)
 *
 * Conducted by teamwork_challenger_m6_1 (Empirical Challenger)
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';

const srcAppPath = path.resolve('dashboard/src/app.js');
const distAppPath = path.resolve('dashboard/dist/app.js');

function createBrowserEnvironment() {
    const domListeners = {};
    const windowListeners = {};
    const elementRegistry = {};

    const mockElement = (id = '', tag = 'DIV') => {
        const el = {
            id,
            tagName: String(tag).toUpperCase(),
            width: 64,
            height: 64,
            style: {},
            classList: {
                contains: () => false,
                add: () => {},
                remove: () => {},
                toggle: () => {}
            },
            innerHTML: '',
            innerText: '',
            textContent: '',
            value: '',
            dataset: {},
            childNodes: [],
            children: [],
            appendChild(c) {
                this.childNodes.push(c);
                this.children.push(c);
                return c;
            },
            removeChild(c) {
                const i = this.childNodes.indexOf(c);
                if (i !== -1) {
                    this.childNodes.splice(i, 1);
                    this.children.splice(i, 1);
                }
                return c;
            },
            querySelectorAll: () => [],
            querySelector: () => null,
            addEventListener: () => {},
            removeEventListener: () => {},
            setAttribute(k, v) { this[k] = v; },
            getAttribute(k) { return this[k] ?? null; },
            getContext(type) {
                if (type === '2d') {
                    if (!this._ctx2d) {
                        this._ctx2d = {
                            createImageData(w, h) {
                                return {
                                    width: w,
                                    height: h,
                                    data: new Uint8ClampedArray(w * h * 4)
                                };
                            },
                            getImageData(sx, sy, sw, sh) {
                                if (!this._imgData || this._imgData.width !== sw || this._imgData.height !== sh) {
                                    this._imgData = {
                                        width: sw,
                                        height: sh,
                                        data: new Uint8ClampedArray(sw * sh * 4)
                                    };
                                }
                                return this._imgData;
                            },
                            putImageData(imgData, dx, dy) {
                                this._imgData = imgData;
                            },
                            clearRect(x, y, w, h) {
                                if (this._imgData && this._imgData.data) {
                                    this._imgData.data.fill(0);
                                }
                            },
                            fillRect() {},
                            drawImage() {}
                        };
                    }
                    return this._ctx2d;
                }
                return null;
            }
        };
        return el;
    };

    const mockDocument = {
        readyState: 'complete',
        body: mockElement('body'),
        getElementById(id) {
            if (!elementRegistry[id]) {
                const isCanvas = id && id.includes('canvas');
                elementRegistry[id] = mockElement(id, isCanvas ? 'CANVAS' : 'DIV');
            }
            return elementRegistry[id];
        },
        querySelector(sel) {
            if (sel && sel.startsWith('#')) {
                return this.getElementById(sel.slice(1));
            }
            return mockElement(sel);
        },
        querySelectorAll(sel) {
            if (sel && sel.includes('canvas')) {
                return Object.values(elementRegistry).filter(el =>
                    el.tagName === 'CANVAS' || (el.id && el.id.startsWith('stego-canvas'))
                );
            }
            return [];
        },
        createElement(tag) {
            return mockElement('', tag);
        },
        addEventListener(event, callback) {
            domListeners[event] = domListeners[event] || [];
            domListeners[event].push(callback);
        }
    };

    const mockWindow = {
        document: mockDocument,
        localStorage: {
            _data: { 'oshoosi_logged_in': 'true' },
            getItem(k) { return this._data[k] ?? null; },
            setItem(k, v) { this._data[k] = String(v); },
            removeItem(k) { delete this._data[k]; },
            clear() { this._data = {}; }
        },
        sessionStorage: {
            _data: {},
            getItem(k) { return this._data[k] ?? null; },
            setItem(k, v) { this._data[k] = String(v); },
            removeItem(k) { delete this._data[k]; },
            clear() { this._data = {}; }
        },
        location: {
            protocol: 'http:',
            host: '127.0.0.1:3030',
            hostname: '127.0.0.1',
            port: '3030',
            pathname: '/',
            search: '',
            hash: '',
            href: 'http://127.0.0.1:3030/'
        },
        navigator: {
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OshoosiClaw/1.0',
            clipboard: { writeText: async () => {} }
        },
        addEventListener(event, callback) {
            windowListeners[event] = windowListeners[event] || [];
            windowListeners[event].push(callback);
        },
        removeEventListener() {},
        setTimeout(fn, ms) {
            if (ms === 4000) {
                return globalThis.setTimeout(fn, ms);
            }
            return 1;
        },
        clearTimeout(id) {
            if (id && id !== 1 && id !== 2) {
                globalThis.clearTimeout(id);
            }
        },
        setInterval() { return 2; },
        clearInterval() {},
        AbortController: globalThis.AbortController,
        fetch: async () => ({
            ok: true,
            status: 200,
            json: async () => ({ status: 'ok', data: [] }),
            text: async () => '{"status":"ok"}'
        }),
        lucide: { createIcons: () => {} },
        vis: {
            Network: function() { return { destroy: () => {}, on: () => {}, fit: () => {} }; },
            DataSet: function(arr) { return { get: () => arr || [], add: () => {}, update: () => {}, clear: () => {} }; }
        },
        Chart: function() { return { update: () => {}, destroy: () => {} }; },
        EventSource: class { constructor() {} addEventListener() {} close() {} },
        renderOwaspHuntingPanel: () => {},
        FileReader: class { readAsText() {} readAsArrayBuffer() {} },
        CustomEvent: class { constructor(t, d) { this.type = t; this.detail = d; } },
        Event: class { constructor(t) { this.type = t; } },
        Blob: class { constructor(p) { this.parts = p; } },
        URL: { createObjectURL: () => 'blob:mock', revokeObjectURL: () => {} },
        crypto: globalThis.crypto || crypto,
        TextEncoder: globalThis.TextEncoder,
        TextDecoder: globalThis.TextDecoder,
        console
    };

    mockWindow.window = mockWindow;
    return { mockWindow, mockDocument, domListeners, windowListeners };
}

function loadAppInEnv(env, filePath = srcAppPath) {
    const code = fs.readFileSync(filePath, 'utf8');
    const script = new vm.Script(code, { filename: 'app.js' });
    const context = vm.createContext(env.mockWindow);
    script.runInContext(context);
    return env.mockWindow;
}

describe('Milestone M6 Empirical Challenger Canvas & Steganography Stress', () => {

    test('Challenge 1: Bit-level roundtrip across payloads of varying sizes (0B, 1B, 16B, 256B, 1024B, 2048B)', async () => {
        const env = createBrowserEnvironment();
        const win = loadAppInEnv(env);
        const { encodeCodeIntoImage, decodeCodeFromImage } = win;

        assert.equal(typeof encodeCodeIntoImage, 'function');
        assert.equal(typeof decodeCodeFromImage, 'function');

        const testSizes = [0, 1, 16, 256, 1024, 2048];

        for (const size of testSizes) {
            const originalBytes = new Uint8Array(size);
            for (let i = 0; i < size; i++) {
                originalBytes[i] = (i * 37 + 13) & 0xFF;
            }

            // 100x100 canvas = 10000 pixels -> 3750 bytes RGB capacity (fits 2048B + 16B header)
            const width = 100;
            const height = 100;
            const imgData = await encodeCodeIntoImage(originalBytes, width, height, null);

            // Invariant: Alpha channel MUST remain strictly 255 (opaque) on all pixels
            for (let p = 0; p < width * height; p++) {
                assert.equal(
                    imgData.data[p * 4 + 3],
                    255,
                    `Alpha channel at pixel ${p} was altered during ${size}-byte encoding!`
                );
            }

            // Decode from image data
            const decodedBytes = await decodeCodeFromImage(imgData, null);

            // Assert bit-for-bit identity
            assert.equal(
                decodedBytes.length,
                size,
                `Decoded length mismatch for size ${size}: got ${decodedBytes.length}`
            );
            assert.ok(
                Buffer.from(decodedBytes).equals(Buffer.from(originalBytes)),
                `Decoded bytes did not match original bytes for payload size ${size}`
            );
        }
    });

    test('Challenge 2: Oversized payload exceeds RGB capacity and throws error', async () => {
        const env = createBrowserEnvironment();
        const win = loadAppInEnv(env);
        const { encodeCodeIntoImage } = win;

        const hugePayload = new Uint8Array(5000); // Exceeds 64x64 canvas RGB capacity (1536 bytes)

        await assert.rejects(
            async () => {
                await encodeCodeIntoImage(hugePayload, 64, 64, null);
            },
            /exceeds canvas RGB capacity/
        );
    });

    test('Challenge 3: Web Crypto AES-GCM bit-level roundtrip, key separation and tamper resistance', async () => {
        const env = createBrowserEnvironment();
        const win = loadAppInEnv(env);
        const { encodeCodeIntoImage, decodeCodeFromImage } = win;
        const webcrypto = win.crypto;

        // Generate 256-bit AES-GCM key A
        const keyA = await webcrypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        // Generate 256-bit AES-GCM key B (adversary / wrong key)
        const keyB = await webcrypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        const secretCode = new TextEncoder().encode('forbid(principal, action, resource) when { context.threat == "breakout" };');
        const imgData = await encodeCodeIntoImage(secretCode, 64, 64, keyA);

        // Verify Alpha is 255
        for (let p = 0; p < 64 * 64; p++) {
            assert.equal(imgData.data[p * 4 + 3], 255);
        }

        // Sub-test A: Decrypt with correct key A -> succeeds with bit-level match
        const decryptedCorrect = await decodeCodeFromImage(imgData, keyA);
        assert.ok(
            Buffer.from(decryptedCorrect).equals(Buffer.from(secretCode)),
            'AES-GCM decrypted bytes must match original secret code'
        );

        // Sub-test B: Decrypt with wrong key B -> fails closed, returns empty Uint8Array
        const decryptedWrongKey = await decodeCodeFromImage(imgData, keyB);
        assert.equal(decryptedWrongKey.length, 0, 'Decryption with wrong key must fail closed and return empty array');

        // Sub-test C: Bit-flip tamper attack in ciphertext LSB
        const tamperedData = {
            width: imgData.width,
            height: imgData.height,
            data: new Uint8ClampedArray(imgData.data)
        };
        // Flip bit at index 200 (in RGB region)
        tamperedData.data[200] ^= 1;

        const decryptedTampered = await decodeCodeFromImage(tamperedData, keyA);
        assert.equal(decryptedTampered.length, 0, 'Tampered ciphertext must fail GCM auth tag check and return empty array');
    });

    test('Challenge 4: Ephemeral memory streaming, in-tick zero wipe, and scrubEphemeralCanvas', async () => {
        const env = createBrowserEnvironment();
        const win = loadAppInEnv(env);
        const { renderEphemeralCodeToCanvas, scrubEphemeralCanvas } = win;

        const canvasId = 'stego-canvas-test-rule-1';
        const canvasEl = env.mockDocument.getElementById(canvasId);

        const secret = 'forbid(principal in "Role::Agent", action, resource);';
        const rendered = await renderEphemeralCodeToCanvas(canvasId, secret);
        assert.equal(rendered, true, 'renderEphemeralCodeToCanvas must return true');

        const ctx = canvasEl.getContext('2d');
        assert.ok(ctx._imgData, 'Canvas 2d context must have image data');
        const nonZeroRendered = ctx._imgData.data.some(b => b > 0);
        assert.ok(nonZeroRendered, 'Rendered canvas must have non-zero pixel data');

        // Explicit scrub
        scrubEphemeralCanvas(canvasId);
        const allZeroAfterScrub = ctx._imgData.data.every(b => b === 0);
        assert.ok(allZeroAfterScrub, 'Canvas pixels must be zeroed after scrubEphemeralCanvas');
        assert.equal(win._stegoBurnTimers[canvasId], undefined, 'Burn timer must be cleared');
    });

    test('Challenge 5: 0-Diff Parity between dashboard/src/app.js and dashboard/dist/app.js', () => {
        const srcContent = fs.readFileSync(srcAppPath);
        const distContent = fs.readFileSync(distAppPath);

        const srcHash = crypto.createHash('sha256').update(srcContent).digest('hex');
        const distHash = crypto.createHash('sha256').update(distContent).digest('hex');

        assert.equal(
            srcHash,
            distHash,
            `WebUI Parity Invariant Violation: SHA-256 mismatch between src/app.js (${srcHash}) and dist/app.js (${distHash})`
        );
    });

    test('Challenge 6: Preservation of Disk Cleanup Banner scheduled/success fix', () => {
        const content = fs.readFileSync(srcAppPath, 'utf8');
        const hasCleanupFix = content.includes("data.status === 'success' || data.status === 'scheduled'");
        assert.equal(
            hasCleanupFix,
            true,
            "CRITICAL REGRESSION: Disk Cleanup banner fix ('data.status === scheduled') was lost or overwritten!"
        );
    });
});
