import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';

// ============================================================================
// Adversarial Challenger Suite: CAGE Governance WebUI Card & Substrate Observability
// ============================================================================

const srcDir = path.resolve('dashboard/src');
const distDir = path.resolve('dashboard/dist');

function computeSha256(filePath) {
    const buffer = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// ============================================================================
// Helper: Browser Environment Mock for CAGE Governance Testing
// ============================================================================
function createCageBrowserEnvironment() {
    const elementRegistry = {};

    const mockElement = (id = '', tag = 'DIV') => {
        const el = {
            id,
            tagName: String(tag).toUpperCase(),
            style: {},
            className: '',
            classList: {
                _classes: new Set(),
                contains(c) { return this._classes.has(c); },
                add(c) { this._classes.add(c); el.className = Array.from(this._classes).join(' '); },
                remove(c) { this._classes.delete(c); el.className = Array.from(this._classes).join(' '); },
                toggle(c) {
                    if (this._classes.has(c)) this.remove(c);
                    else this.add(c);
                }
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
            getAttribute(k) { return this[k] ?? null; }
        };
        return el;
    };

    // Pre-populate CAGE DOM elements matching index.html
    const cageCard = mockElement('cage-governance-card', 'DIV');
    const cageBody = mockElement('cage-governance-body', 'DIV');
    const polEl = mockElement('cage-policy-version', 'DIV');
    polEl.textContent = 'None (Unpinned)';
    const cbfEl = mockElement('cage-cbf-indicator', 'DIV');
    cbfEl.textContent = 'h >= 0.00 (Safe)';
    const sealsEl = mockElement('cage-seals-count', 'DIV');
    sealsEl.textContent = '0 / 0';
    const refreshBtn = mockElement('refresh-cage-stats-btn', 'BUTTON');

    elementRegistry['cage-governance-card'] = cageCard;
    elementRegistry['cage-governance-body'] = cageBody;
    elementRegistry['cage-policy-version'] = polEl;
    elementRegistry['cage-cbf-indicator'] = cbfEl;
    elementRegistry['cage-seals-count'] = sealsEl;
    elementRegistry['refresh-cage-stats-btn'] = refreshBtn;

    const mockDocument = {
        readyState: 'loading',
        body: mockElement('body', 'BODY'),
        getElementById(id) {
            if (elementRegistry[id] === null) return null;
            if (!elementRegistry[id]) {
                elementRegistry[id] = mockElement(id, 'DIV');
            }
            return elementRegistry[id];
        },
        querySelector(sel) {
            if (sel && sel.startsWith('#')) {
                return this.getElementById(sel.slice(1));
            }
            return mockElement(sel, 'DIV');
        },
        querySelectorAll: () => [],
        createElement(tag) { return mockElement('', tag); },
        addEventListener: () => {}
    };

    let fetchMockHandler = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ status: 'ok' })
    });

    const mockWindow = {
        document: mockDocument,
        localStorage: {
            _data: {},
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
        navigator: { userAgent: 'OshoosiClaw-Adversarial-Harness/1.0' },
        addEventListener: () => {},
        removeEventListener: () => {},
        setTimeout: () => 1,
        clearTimeout: () => {},
        setInterval: () => 2,
        clearInterval: () => {},
        fetch: (...args) => fetchMockHandler(...args),
        lucide: { createIcons: () => {} },
        vis: {
            Network: function() { return { destroy: () => {}, on: () => {}, fit: () => {} }; },
            DataSet: function() { return { get: () => [], add: () => {}, update: () => {}, clear: () => {} }; }
        },
        Chart: function() { return { update: () => {}, destroy: () => {} }; },
        EventSource: class { constructor() {} addEventListener() {} close() {} },
        console: {
            ...console,
            warn: () => {},
            error: () => {},
            log: () => {}
        }
    };

    mockWindow.window = mockWindow;

    return {
        mockWindow,
        mockDocument,
        elementRegistry,
        setFetchMock(fn) { fetchMockHandler = fn; }
    };
}

// ============================================================================
// 1. Strict Byte Parity Between src and dist (0-Diff Invariant)
// ============================================================================
describe('CAGE WebUI: Strict Byte-for-Byte SHA-256 Parity Invariant', () => {
    it('should assert byte-for-byte SHA256 equality for index.html', () => {
        const srcPath = path.join(srcDir, 'index.html');
        const distPath = path.join(distDir, 'index.html');
        assert.ok(fs.existsSync(srcPath), 'src/index.html must exist');
        assert.ok(fs.existsSync(distPath), 'dist/index.html must exist');
        const srcHash = computeSha256(srcPath);
        const distHash = computeSha256(distPath);
        assert.strictEqual(srcHash, distHash, 'index.html byte hash mismatch between src and dist');
    });

    it('should assert byte-for-byte SHA256 equality for styles.css', () => {
        const srcPath = path.join(srcDir, 'styles.css');
        const distPath = path.join(distDir, 'styles.css');
        assert.ok(fs.existsSync(srcPath), 'src/styles.css must exist');
        assert.ok(fs.existsSync(distPath), 'dist/styles.css must exist');
        const srcHash = computeSha256(srcPath);
        const distHash = computeSha256(distPath);
        assert.strictEqual(srcHash, distHash, 'styles.css byte hash mismatch between src and dist');
    });

    it('should assert byte-for-byte SHA256 equality for style.css', () => {
        const srcPath = path.join(srcDir, 'style.css');
        const distPath = path.join(distDir, 'style.css');
        assert.ok(fs.existsSync(srcPath), 'src/style.css must exist');
        assert.ok(fs.existsSync(distPath), 'dist/style.css must exist');
        const srcHash = computeSha256(srcPath);
        const distHash = computeSha256(distPath);
        assert.strictEqual(srcHash, distHash, 'style.css byte hash mismatch between src and dist');
    });

    it('should assert byte-for-byte SHA256 equality for app.js', () => {
        const srcPath = path.join(srcDir, 'app.js');
        const distPath = path.join(distDir, 'app.js');
        assert.ok(fs.existsSync(srcPath), 'src/app.js must exist');
        assert.ok(fs.existsSync(distPath), 'dist/app.js must exist');
        const srcHash = computeSha256(srcPath);
        const distHash = computeSha256(distPath);
        assert.strictEqual(srcHash, distHash, 'app.js byte hash mismatch between src and dist');
    });
});

// ============================================================================
// 2. DOM Structure, Unique Contract IDs & Well-Formed Tag Balance
// ============================================================================
describe('CAGE WebUI: DOM Structure & HTML Integrity', () => {
    ['src', 'dist'].forEach((targetDirName) => {
        describe(`Target: dashboard/${targetDirName}`, () => {
            const htmlPath = path.resolve(`dashboard/${targetDirName}/index.html`);
            const html = fs.readFileSync(htmlPath, 'utf8');

            it('should verify #cage-governance-card and required child contract IDs are strictly unique in the DOM', () => {
                const requiredIds = [
                    'cage-governance-card',
                    'cage-policy-version',
                    'cage-cbf-indicator',
                    'cage-seals-count'
                ];

                for (const id of requiredIds) {
                    const idRegex = new RegExp(`id=["']${id}["']`, 'g');
                    const matches = html.match(idRegex);
                    assert.ok(matches, `DOM must contain element with id="${id}" in ${targetDirName}/index.html`);
                    assert.strictEqual(
                        matches.length,
                        1,
                        `Element id="${id}" must be strictly unique in DOM (found ${matches.length} occurrences in ${targetDirName}/index.html)`
                    );
                }
            });

            it('should verify child elements are strictly nested inside #cage-governance-card container', () => {
                const cardStart = html.indexOf('id="cage-governance-card"');
                assert.ok(cardStart !== -1, 'Must find cage-governance-card in index.html');

                // Find closing </div> for the card container
                const afterCard = html.slice(cardStart);
                const nextSectionIndex = afterCard.indexOf('class="main-grid"');
                assert.ok(nextSectionIndex !== -1, 'Must locate subsequent section to bound card scope');
                const cardScope = afterCard.slice(0, nextSectionIndex);

                const requiredChildren = [
                    'cage-policy-version',
                    'cage-cbf-indicator',
                    'cage-seals-count',
                    'refresh-cage-stats-btn'
                ];

                for (const childId of requiredChildren) {
                    assert.ok(
                        cardScope.includes(`id="${childId}"`),
                        `Child #${childId} must be nested inside #cage-governance-card scope in ${targetDirName}`
                    );
                }
            });

            it('should verify balanced opening and closing tags in #cage-governance-card subtree (tag parser assertion)', () => {
                // Extract the exact HTML block for #cage-governance-card
                const cardStartIndex = html.indexOf('<div class="card glass shadow-glow mb-4" id="cage-governance-card"');
                assert.ok(cardStartIndex !== -1, 'Must find exact start tag of #cage-governance-card');

                // Bounded search up to next sibling element (main-grid)
                const mainGridIndex = html.indexOf('<div class="main-grid">', cardStartIndex);
                assert.ok(mainGridIndex !== -1, 'Must find main-grid after cage card');
                const cardSnippet = html.slice(cardStartIndex, mainGridIndex).trim();

                // Tokenize HTML tags: <tag ...> or </tag>
                const tagRegex = /<\/?([a-zA-Z0-9]+)(\s+[^>]*)?\/?>/g;
                const voidTags = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
                const stack = [];
                let match;

                while ((match = tagRegex.exec(cardSnippet)) !== null) {
                    const fullTag = match[0];
                    const tagName = match[1].toLowerCase();
                    const isClosing = fullTag.startsWith('</');
                    const isSelfClosing = fullTag.endsWith('/>') || voidTags.has(tagName);

                    if (isClosing) {
                        assert.ok(stack.length > 0, `Unexpected closing tag </${tagName}> with empty stack in ${targetDirName}`);
                        const popped = stack.pop();
                        assert.strictEqual(
                            popped,
                            tagName,
                            `Mismatched closing tag: expected </${popped}> but encountered </${tagName}> in ${targetDirName}`
                        );
                    } else if (!isSelfClosing) {
                        stack.push(tagName);
                    }
                }

                assert.strictEqual(
                    stack.length,
                    0,
                    `Unclosed tags detected in #cage-governance-card: [${stack.join(', ')}] in ${targetDirName}`
                );
            });
        });
    });
});

// ============================================================================
// 3. CSS & Style Invariants
// ============================================================================
describe('CAGE WebUI: CSS & Style Invariants', () => {
    ['src', 'dist'].forEach((targetDirName) => {
        describe(`Target: dashboard/${targetDirName}`, () => {
            const stylesCssPath = path.resolve(`dashboard/${targetDirName}/styles.css`);
            const styleCssPath = path.resolve(`dashboard/${targetDirName}/style.css`);
            const stylesCss = fs.readFileSync(stylesCssPath, 'utf8');
            const styleCss = fs.readFileSync(styleCssPath, 'utf8');

            it('should verify all CAGE element ID selectors exist in styles.css and style.css', () => {
                const requiredSelectors = [
                    '#cage-governance-card',
                    '#cage-policy-version',
                    '#cage-cbf-indicator',
                    '#cage-seals-count'
                ];

                for (const sel of requiredSelectors) {
                    assert.ok(
                        stylesCss.includes(sel),
                        `Selector ${sel} must exist in ${targetDirName}/styles.css`
                    );
                    assert.ok(
                        styleCss.includes(sel),
                        `Selector ${sel} must exist in ${targetDirName}/style.css`
                    );
                }
            });

            it('should verify CAGE-specific classes and dynamic state classes exist in styles.css', () => {
                const requiredClasses = [
                    '.cage-stat-box',
                    'cbf-warning',
                    'cbf-danger'
                ];

                for (const cls of requiredClasses) {
                    assert.ok(
                        stylesCss.includes(cls),
                        `Class rule ${cls} must exist in ${targetDirName}/styles.css`
                    );
                    assert.ok(
                        styleCss.includes(cls),
                        `Class rule ${cls} must exist in ${targetDirName}/style.css`
                    );
                }
            });

            it('should verify CSS rules define necessary visual presentation properties', () => {
                // Verify card border, blur, and background
                assert.ok(stylesCss.includes('border: 1px solid rgba(56, 189, 248'), 'Must define CAGE cyan border');
                assert.ok(stylesCss.includes('backdrop-filter: blur'), 'Must define glassmorphism blur');
                assert.ok(stylesCss.includes('border-radius: 12px'), 'Must define rounded corners');

                // Verify monospace fonts for cryptographic hash / numeric telemetry
                assert.ok(stylesCss.includes("font-family: 'JetBrains Mono', monospace"), 'Must use monospace font for policy version and telemetry');

                // Verify warning/danger colors
                assert.ok(stylesCss.includes('#f59e0b'), 'Must define amber warning color for cbf-warning');
                assert.ok(stylesCss.includes('#ef4444'), 'Must define red danger color for cbf-danger');
            });

            it('should verify shared layout classes used on CAGE card resolve in main stylesheet', () => {
                const sharedCardClasses = [
                    'card',
                    'glass',
                    'shadow-glow',
                    'card-header',
                    'badge',
                    'btn-text',
                    'card-body'
                ];

                for (const cls of sharedCardClasses) {
                    assert.ok(
                        styleCss.includes(`.${cls}`),
                        `Shared component class .${cls} must exist in ${targetDirName}/style.css`
                    );
                }
            });
        });
    });
});

// ============================================================================
// 4. JavaScript Resilience: Adversarial Fuzzing of updateCageGovernanceUI and refreshCageGovernanceUI
// ============================================================================
describe('CAGE WebUI: JavaScript Resilience & Adversarial Fuzzing', () => {
    ['src', 'dist'].forEach((targetDirName) => {
        describe(`Target: dashboard/${targetDirName}/app.js`, () => {
            const appCode = fs.readFileSync(path.resolve(`dashboard/${targetDirName}/app.js`), 'utf8');

            function loadAppInCleanEnv() {
                const env = createCageBrowserEnvironment();
                const context = vm.createContext(env.mockWindow);
                const script = new vm.Script(appCode, { filename: `${targetDirName}/app.js` });
                script.runInContext(context);
                return env;
            }

            it('should export window.updateCageGovernanceUI and window.refreshCageGovernanceUI as functions', () => {
                const env = loadAppInCleanEnv();
                assert.strictEqual(typeof env.mockWindow.updateCageGovernanceUI, 'function', 'updateCageGovernanceUI must be a function on window');
                assert.strictEqual(typeof env.mockWindow.refreshCageGovernanceUI, 'function', 'refreshCageGovernanceUI must be a function on window');
            });

            it('should handle null and undefined stats in updateCageGovernanceUI without throwing', () => {
                const env = loadAppInCleanEnv();
                const fn = env.mockWindow.updateCageGovernanceUI;

                assert.doesNotThrow(() => fn(null), 'Must not throw on null stats');
                assert.doesNotThrow(() => fn(undefined), 'Must not throw on undefined stats');
                assert.doesNotThrow(() => fn(false), 'Must not throw on false stats');
                assert.doesNotThrow(() => fn(0), 'Must not throw on 0 stats');
                assert.doesNotThrow(() => fn(''), 'Must not throw on empty string stats');
            });

            it('should handle empty object and partial payloads in updateCageGovernanceUI gracefully', () => {
                const env = loadAppInCleanEnv();
                const fn = env.mockWindow.updateCageGovernanceUI;

                assert.doesNotThrow(() => fn({}), 'Must not throw on empty object');
                assert.doesNotThrow(() => fn({ unrelated_key: 'foo' }), 'Must not throw on unexpected keys');
                assert.doesNotThrow(() => fn({ policy_version: null }), 'Must not throw on null policy_version');
                assert.doesNotThrow(() => fn({ cbf_barrier_val: null }), 'Must not throw on null cbf_barrier_val');
                assert.doesNotThrow(() => fn({ seals_text: null }), 'Must not throw on null seals_text');
            });

            it('should handle NaN, non-numeric strings, and extreme numeric values for cbf_barrier_val', () => {
                const env = loadAppInCleanEnv();
                const fn = env.mockWindow.updateCageGovernanceUI;
                const cbfEl = env.mockDocument.getElementById('cage-cbf-indicator');

                // NaN budget value
                assert.doesNotThrow(() => fn({ cbf_barrier_val: NaN }));
                assert.ok(cbfEl.textContent.includes('NaN'), 'Should format NaN gracefully');
                assert.strictEqual(cbfEl.className, 'cbf-danger', 'NaN barrier value should fail closed as breach (cbf-danger)');

                // Corrupted string numeric
                assert.doesNotThrow(() => fn({ cbf_barrier_val: 'corrupted-barrier-val' }));
                assert.ok(cbfEl.textContent.includes('NaN'), 'Non-numeric string should yield NaN');
                assert.strictEqual(cbfEl.className, 'cbf-danger', 'Non-numeric barrier must fail closed as cbf-danger');

                // Negative value (Breach condition)
                fn({ cbf_barrier_val: -12.3456 });
                assert.strictEqual(cbfEl.textContent, 'h = -12.35 (Breach)');
                assert.strictEqual(cbfEl.className, 'cbf-danger');

                // Zero barrier (Exact boundary - Safe)
                fn({ cbf_barrier_val: 0 });
                assert.strictEqual(cbfEl.textContent, 'h = 0.00 (Safe)');
                assert.strictEqual(cbfEl.className, '');

                // Positive barrier (Safe condition)
                fn({ cbf_barrier_val: 42.1 });
                assert.strictEqual(cbfEl.textContent, 'h = 42.10 (Safe)');
                assert.strictEqual(cbfEl.className, '');

                // Extreme values
                assert.doesNotThrow(() => fn({ cbf_barrier_val: Number.MAX_SAFE_INTEGER }));
                assert.doesNotThrow(() => fn({ cbf_barrier_val: -Number.MAX_VALUE }));
                assert.doesNotThrow(() => fn({ cbf_barrier_val: Infinity }));
                assert.doesNotThrow(() => fn({ cbf_barrier_val: -Infinity }));
            });

            it('should update policy version and seals text correctly under valid payloads', () => {
                const env = loadAppInCleanEnv();
                const fn = env.mockWindow.updateCageGovernanceUI;

                const polEl = env.mockDocument.getElementById('cage-policy-version');
                const sealsEl = env.mockDocument.getElementById('cage-seals-count');

                fn({
                    policy_version: '3f7a1b9c8e2d4f6a',
                    cbf_barrier_val: 18.5,
                    seals_text: '27 / 27'
                });

                assert.strictEqual(polEl.textContent, '3f7a1b9c8e2d4f6a');
                assert.strictEqual(sealsEl.textContent, '27 / 27');
            });

            it('should not throw if DOM elements are missing or deleted (DOM resilient)', () => {
                const env = loadAppInCleanEnv();
                // Simulate missing elements
                env.elementRegistry['cage-policy-version'] = null;
                env.elementRegistry['cage-cbf-indicator'] = null;
                env.elementRegistry['cage-seals-count'] = null;

                assert.doesNotThrow(() => {
                    env.mockWindow.updateCageGovernanceUI({
                        policy_version: 'test_version',
                        cbf_barrier_val: 10,
                        seals_text: '5 / 5'
                    });
                }, 'Must handle missing DOM nodes without throwing TypeError');
            });

            it('should withstand prototype pollution attempts in updateCageGovernanceUI', () => {
                const env = loadAppInCleanEnv();
                const hostilePayload = JSON.parse('{"__proto__":{"polluted":true},"policy_version":"pinned-v1"}');

                assert.doesNotThrow(() => env.mockWindow.updateCageGovernanceUI(hostilePayload));
                assert.strictEqual({}.polluted, undefined, 'Object prototype must not be polluted');
            });

            it('should handle total network failure in refreshCageGovernanceUI without unhandled rejection', async () => {
                const env = loadAppInCleanEnv();
                env.setFetchMock(async () => {
                    throw new Error('TypeError: Failed to fetch (Network connection refused)');
                });

                await assert.doesNotReject(
                    async () => { await env.mockWindow.refreshCageGovernanceUI(); },
                    'refreshCageGovernanceUI must not reject on network drop'
                );
            });

            it('should handle HTTP 500 server error in refreshCageGovernanceUI gracefully', async () => {
                const env = loadAppInCleanEnv();
                env.setFetchMock(async (url) => ({
                    ok: false,
                    status: 500,
                    statusText: 'Internal Server Error',
                    json: async () => ({ error: 'CAGE substrate pipeline down' }),
                    text: async () => '500 Internal Server Error'
                }));

                await assert.doesNotReject(
                    async () => { await env.mockWindow.refreshCageGovernanceUI(); },
                    'refreshCageGovernanceUI must handle HTTP 500 without throwing'
                );

                // Check default fallback values applied
                const polEl = env.mockDocument.getElementById('cage-policy-version');
                const sealsEl = env.mockDocument.getElementById('cage-seals-count');
                assert.strictEqual(polEl.textContent, 'None (Unpinned)');
                assert.strictEqual(sealsEl.textContent, '0 / 0');
            });

            it('should handle corrupted non-JSON responses in refreshCageGovernanceUI', async () => {
                const env = loadAppInCleanEnv();
                env.setFetchMock(async () => ({
                    ok: true,
                    status: 200,
                    json: async () => { throw new SyntaxError('Unexpected token < in JSON at position 0'); },
                    text: async () => '<html><body>Proxy Error</body></html>'
                }));

                await assert.doesNotReject(
                    async () => { await env.mockWindow.refreshCageGovernanceUI(); },
                    'refreshCageGovernanceUI must catch JSON parsing syntax errors without crashing'
                );
            });

            it('should handle null/empty response payloads in refreshCageGovernanceUI', async () => {
                const env = loadAppInCleanEnv();
                env.setFetchMock(async () => ({
                    ok: true,
                    status: 200,
                    json: async () => null,
                    text: async () => 'null'
                }));

                await assert.doesNotReject(
                    async () => { await env.mockWindow.refreshCageGovernanceUI(); },
                    'refreshCageGovernanceUI must handle null json() response without crashing'
                );
            });

            it('should successfully update UI from /governance/stats endpoint', async () => {
                const env = loadAppInCleanEnv();
                env.setFetchMock(async (url) => {
                    if (url === '/governance/stats') {
                        return {
                            ok: true,
                            status: 200,
                            json: async () => ({
                                policy_version: '9f8e7d6c5b4a3120',
                                cbf_barrier_val: 7.25,
                                seals_text: '14 / 14'
                            })
                        };
                    }
                    return { ok: false, status: 404 };
                });

                await env.mockWindow.refreshCageGovernanceUI();

                const polEl = env.mockDocument.getElementById('cage-policy-version');
                const cbfEl = env.mockDocument.getElementById('cage-cbf-indicator');
                const sealsEl = env.mockDocument.getElementById('cage-seals-count');

                assert.strictEqual(polEl.textContent, '9f8e7d6c5b4a3120');
                assert.strictEqual(cbfEl.textContent, 'h = 7.25 (Safe)');
                assert.strictEqual(sealsEl.textContent, '14 / 14');
            });

            it('should seamlessly fall back to /governance/policy-version and /governance/trace/verify when stats is 404', async () => {
                const env = loadAppInCleanEnv();
                env.setFetchMock(async (url) => {
                    if (url === '/governance/stats') {
                        return { ok: false, status: 404 };
                    }
                    if (url === '/governance/policy-version') {
                        return {
                            ok: true,
                            status: 200,
                            json: async () => ({ active_version_id: 'deadbeef01234567' })
                        };
                    }
                    if (url === '/governance/trace/verify') {
                        return {
                            ok: true,
                            status: 200,
                            json: async () => ({ verified: true, trace_count: 53 })
                        };
                    }
                    return { ok: false, status: 404 };
                });

                await env.mockWindow.refreshCageGovernanceUI();

                const polEl = env.mockDocument.getElementById('cage-policy-version');
                const cbfEl = env.mockDocument.getElementById('cage-cbf-indicator');
                const sealsEl = env.mockDocument.getElementById('cage-seals-count');

                assert.strictEqual(polEl.textContent, 'deadbeef01234567');
                assert.strictEqual(cbfEl.textContent, 'h = 10.00 (Safe)');
                assert.strictEqual(sealsEl.textContent, '53 / 53');
            });
        });
    });
});
