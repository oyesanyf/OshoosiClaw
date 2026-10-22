import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';

// ============================================================================
// Suite 1: WebUI 0-Diff Parity Invariant (Feature 16)
// ============================================================================
describe('WebUI 0-Diff Parity Invariant (Feature 16)', () => {
    const srcDir = path.resolve('dashboard/src');
    const distDir = path.resolve('dashboard/dist');

    function getFilesRecursively(dir) {
        let results = [];
        const list = fs.readdirSync(dir, { withFileTypes: true });
        for (const dirent of list) {
            const fullPath = path.join(dir, dirent.name);
            if (dirent.isDirectory()) {
                results = results.concat(getFilesRecursively(fullPath));
            } else {
                results.push(fullPath);
            }
        }
        return results;
    }

    function computeSha256(filePath) {
        const buffer = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }

    it('should confirm dashboard/src and dashboard/dist directories both exist', () => {
        assert.ok(fs.existsSync(srcDir), 'dashboard/src must exist');
        assert.ok(fs.existsSync(distDir), 'dashboard/dist must exist');
    });

    it('should assert byte-for-byte SHA256 equality for index.html', () => {
        const srcHash = computeSha256(path.join(srcDir, 'index.html'));
        const distHash = computeSha256(path.join(distDir, 'index.html'));
        assert.strictEqual(srcHash, distHash, 'index.html in src and dist must have identical SHA-256');
    });

    it('should assert byte-for-byte SHA256 equality for app.js', () => {
        const srcHash = computeSha256(path.join(srcDir, 'app.js'));
        const distHash = computeSha256(path.join(distDir, 'app.js'));
        assert.strictEqual(srcHash, distHash, 'app.js in src and dist must have identical SHA-256');
    });

    it('should assert byte-for-byte SHA256 equality for all modular views/*.js', () => {
        const requiredViews = ['dlp.js', 'mesh.js', 'har.js', 'adversarial.js'];
        for (const viewName of requiredViews) {
            const srcPath = path.join(srcDir, 'views', viewName);
            const distPath = path.join(distDir, 'views', viewName);
            assert.ok(fs.existsSync(srcPath), `dashboard/src/views/${viewName} must exist`);
            assert.ok(fs.existsSync(distPath), `dashboard/dist/views/${viewName} must exist`);
            const srcHash = computeSha256(srcPath);
            const distHash = computeSha256(distPath);
            assert.strictEqual(srcHash, distHash, `views/${viewName} in src and dist must have identical SHA-256`);
        }
    });

    it('should assert byte-for-byte SHA256 equality for all style and asset files', () => {
        const srcFiles = getFilesRecursively(srcDir);
        const distFiles = getFilesRecursively(distDir);

        const relSrcFiles = srcFiles.map(f => path.relative(srcDir, f)).sort();
        const relDistFiles = distFiles.map(f => path.relative(distDir, f)).sort();

        assert.deepStrictEqual(relSrcFiles, relDistFiles, 'File lists in src and dist must be identical');

        for (const relFile of relSrcFiles) {
            const srcHash = computeSha256(path.join(srcDir, relFile));
            const distHash = computeSha256(path.join(distDir, relFile));
            assert.strictEqual(srcHash, distHash, `File ${relFile} in src and dist must have identical SHA-256`);
        }
    });
});

// ============================================================================
// Suite 2: WebUI Modular Views Runtime Evaluation & Window Export Integrity
// ============================================================================
describe('WebUI Modular Views Runtime Evaluation & Window Export Integrity', () => {
    function createBrowserEnvironment() {
        const domListeners = {};
        const windowListeners = {};

        const mockElement = (id = '') => {
            const el = {
                id,
                tagName: 'DIV',
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
                firstChild: null,
                lastChild: null,
                scrollTop: 0,
                scrollHeight: 100,
                appendChild(c) {
                    this.childNodes.push(c);
                    this.children.push(c);
                    this.firstChild = this.childNodes[0] || null;
                    this.lastChild = this.childNodes[this.childNodes.length - 1] || null;
                    return c;
                },
                removeChild(c) {
                    const i = this.childNodes.indexOf(c);
                    if (i !== -1) {
                        this.childNodes.splice(i, 1);
                        this.children.splice(i, 1);
                    }
                    this.firstChild = this.childNodes[0] || null;
                    this.lastChild = this.childNodes[this.childNodes.length - 1] || null;
                    return c;
                },
                querySelectorAll: () => [],
                querySelector: () => null,
                addEventListener: () => {},
                removeEventListener: () => {},
                focus: () => {},
                click: () => {},
                setAttribute: () => {},
                getAttribute: () => null
            };
            return el;
        };

        const mockDocument = {
            readyState: 'loading',
            body: mockElement('body'),
            getElementById(id) {
                return mockElement(id);
            },
            querySelector(sel) {
                return mockElement(sel);
            },
            querySelectorAll() {
                return [];
            },
            createElement(tag) {
                const el = mockElement(tag);
                el.tagName = String(tag).toUpperCase();
                return el;
            },
            addEventListener(event, callback) {
                domListeners[event] = domListeners[event] || [];
                domListeners[event].push(callback);
            }
        };

        const mockLocalStorage = {
            _data: { 'oshoosi_logged_in': 'true' },
            getItem(k) { return this._data[k] ?? null; },
            setItem(k, v) { this._data[k] = String(v); },
            removeItem(k) { delete this._data[k]; },
            clear() { this._data = {}; }
        };

        const mockWindow = {
            document: mockDocument,
            localStorage: mockLocalStorage,
            sessionStorage: mockLocalStorage,
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
            setTimeout(fn) { return 1; },
            clearTimeout() {},
            setInterval(fn) { return 2; },
            clearInterval() {},
            fetch: async () => ({
                ok: true,
                status: 200,
                json: async () => ({ status: 'ok', data: [], peer_count: 5, total_tests_executed: 2250, passed_tests: 2250, failed_tests: 0 }),
                text: async () => '{"status":"ok"}'
            }),
            lucide: {
                createIcons: () => {}
            },
            vis: {
                Network: function() { return { destroy: () => {}, on: () => {}, fit: () => {} }; },
                DataSet: function(arr) { return { get: () => arr || [], add: () => {}, update: () => {}, clear: () => {} }; }
            },
            Chart: function() {
                return { update: () => {}, destroy: () => {} };
            },
            EventSource: class EventSource {
                constructor() {}
                addEventListener() {}
                close() {}
            },
            renderOwaspHuntingPanel: () => {},
            FileReader: class FileReader {
                readAsText() {}
                readAsArrayBuffer() {}
            },
            CustomEvent: class CustomEvent { constructor(t, d) { this.type = t; this.detail = d; } },
            Event: class Event { constructor(t) { this.type = t; } },
            Blob: class Blob { constructor(p) { this.parts = p; } },
            URL: { createObjectURL: () => 'blob:mock', revokeObjectURL: () => {} },
            console
        };

        mockWindow.window = mockWindow;
        return { mockWindow, mockDocument, domListeners, windowListeners };
    }

    const scriptOrder = [
        'app.js',
        'views/mesh.js',
        'views/har.js',
        'views/adversarial.js',
        'views/dlp.js'
    ];

    ['src', 'dist'].forEach((targetDirName) => {
        const baseDir = path.resolve(`dashboard/${targetDirName}`);

        describe(`Target: dashboard/${targetDirName}`, () => {
            it(`should evaluate app.js and all view scripts without ReferenceError or SyntaxError`, () => {
                const env = createBrowserEnvironment();
                const context = vm.createContext(env.mockWindow);

                for (const relPath of scriptOrder) {
                    const fullPath = path.join(baseDir, relPath);
                    assert.ok(fs.existsSync(fullPath), `${relPath} must exist in ${baseDir}`);
                    const code = fs.readFileSync(fullPath, 'utf8');

                    assert.doesNotThrow(() => {
                        vm.runInContext(code, context, { filename: `${targetDirName}/${relPath}` });
                    }, `Evaluation of ${relPath} in dashboard/${targetDirName} threw an unexpected runtime or syntax error`);
                }
            });

            it(`should verify window.* function exports across mesh, har, adversarial, and dlp`, () => {
                const env = createBrowserEnvironment();
                const context = vm.createContext(env.mockWindow);

                for (const relPath of scriptOrder) {
                    const fullPath = path.join(baseDir, relPath);
                    const code = fs.readFileSync(fullPath, 'utf8');
                    vm.runInContext(code, context, { filename: `${targetDirName}/${relPath}` });
                }

                // 1. Mesh view exports
                const expectedMeshMethods = [
                    'renderMeshView',
                    'updateMeshConnectionIndicators',
                    'activateMeshHologram',
                    'computeMeshEffectivenessClient',
                    'getLiveMeshHostCount',
                    'updateLiveMeshEffectivenessUI',
                    'selectMeshEffectivenessScale',
                    'refreshMeshEffectivenessCard'
                ];
                for (const method of expectedMeshMethods) {
                    assert.strictEqual(
                        typeof env.mockWindow[method],
                        'function',
                        `Expected window.${method} to be a function in dashboard/${targetDirName}`
                    );
                }

                // 2. Closed-Form Mesh Defense Model E(N,t) functional verification
                const eff = env.mockWindow.computeMeshEffectivenessClient(10, 1.0, 2.0);
                assert.ok(eff && typeof eff === 'object', 'computeMeshEffectivenessClient must return an object');
                assert.strictEqual(eff.n_nodes, 10, 'n_nodes must equal 10');
                assert.ok(typeof eff.e_unified_pct === 'number', 'e_unified_pct must be numeric');
                assert.ok(eff.e_unified_pct >= 0 && eff.e_unified_pct <= 100, 'e_unified_pct must be in [0, 100]');
                assert.ok(typeof eff.i_rl_pct === 'number', 'i_rl_pct must be numeric');
                assert.ok(typeof eff.tau_prop_ms === 'number' && eff.tau_prop_ms > 0, 'tau_prop_ms must be positive');

                // 3. HAR view exports
                const expectedHarMethods = [
                    'renderHarTrafficView',
                    'renderHarTrafficTable',
                    'ensureHarContinuousPolling',
                    'inspectHarEntryRow',
                    'closeHarInspector',
                    'openSelectedHarInSiquery',
                    'toggleHarAutoUpdate',
                    'refreshHarTrafficNow',
                    'handleHarFileUpload',
                    'exportLiveHarFile',
                    'openHarHostInSiquery',
                    'onHarFilterChange'
                ];
                for (const method of expectedHarMethods) {
                    assert.strictEqual(
                        typeof env.mockWindow[method],
                        'function',
                        `Expected window.${method} to be a function in dashboard/${targetDirName}`
                    );
                }

                // 4. Adversarial view exports
                const expectedAdversarialMethods = [
                    'renderAdversarialTestsView',
                    'runSelectedAdversarialSuite',
                    'runAdversarialSuite',
                    'stopAdversarialTestRun',
                    'toggleAdversarialAutonomous',
                    'clearAdversarialTerminal',
                    'exportAdversarialTerminalOutput'
                ];
                for (const method of expectedAdversarialMethods) {
                    assert.strictEqual(
                        typeof env.mockWindow[method],
                        'function',
                        `Expected window.${method} to be a function in dashboard/${targetDirName}`
                    );
                }

                // 5. DLP view exports
                const expectedDlpMethods = [
                    'renderDlpView',
                    'submitDlpInspection',
                    'loadDlpSamplePayload',
                    'handleDlpInspectFileUpload',
                    'handleDlpCrownJewelFileUpload',
                    'registerDlpCrownJewel',
                    'testCrownJewelExfilBlock',
                    'runDlpLiveHarSweep',
                    'runDlpExfilSimulationGauntlet',
                    'updateDlpPolicyMode',
                    'onDlpFilterChange'
                ];
                for (const method of expectedDlpMethods) {
                    assert.strictEqual(
                        typeof env.mockWindow[method],
                        'function',
                        `Expected window.${method} to be a function in dashboard/${targetDirName}`
                    );
                }
            });
        });
    });
});
