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
// Shared Browser Environment Mock for Evaluation
// ============================================================================
function createBrowserEnvironment() {
    const domListeners = {};
    const windowListeners = {};

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

        const elementRegistry = {};
        const mockDocument = {
            readyState: 'loading',
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
                    const id = sel.slice(1);
                    return this.getElementById(id);
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
                const el = mockElement('', tag);
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
            crypto: globalThis.crypto || crypto,
            TextEncoder: globalThis.TextEncoder,
            TextDecoder: globalThis.TextDecoder,
            console
        };

    mockWindow.window = mockWindow;
    return { mockWindow, mockDocument, domListeners, windowListeners };
}

// ============================================================================
// Suite 2: WebUI Modular Views Runtime Evaluation & Window Export Integrity
// ============================================================================
describe('WebUI Modular Views Runtime Evaluation & Window Export Integrity', () => {
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

                assert.ok(env.mockWindow.osoosiRateLimit, `Expected window.osoosiRateLimit to exist in dashboard/${targetDirName}`);
                assert.strictEqual(
                    typeof env.mockWindow.osoosiRateLimit.rejectRateLimit,
                    'function',
                    `Expected window.osoosiRateLimit.rejectRateLimit to be a function in dashboard/${targetDirName}`
                );
                assert.strictEqual(
                    typeof env.mockWindow.osoosiRateLimit.rejectAllRateLimits,
                    'function',
                    `Expected window.osoosiRateLimit.rejectAllRateLimits to be a function in dashboard/${targetDirName}`
                );
                assert.strictEqual(
                    typeof env.mockWindow.osoosiRateLimit.evaluateScenario,
                    'function',
                    `Expected window.osoosiRateLimit.evaluateScenario to be a function in dashboard/${targetDirName}`
                );
                assert.strictEqual(
                    typeof env.mockWindow.rejectHarRateLimit,
                    'function',
                    `Expected window.rejectHarRateLimit to be a function in dashboard/${targetDirName}`
                );

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
                    'onDlpFilterChange',
                    'applyDlpAutonomyPreset',
                    'saveCustomDlpAutonomySettings',
                    'syncDlpAutonomyCardsFromPolicy'
                ];
                for (const method of expectedDlpMethods) {
                    assert.strictEqual(
                        typeof env.mockWindow[method],
                        'function',
                        `Expected window.${method} to be a function in dashboard/${targetDirName}`
                    );
                }

                assert.ok(env.mockWindow.osoosiDlp, `Expected window.osoosiDlp to exist in dashboard/${targetDirName}`);
                assert.strictEqual(
                    typeof env.mockWindow.osoosiDlp.releaseEvent,
                    'function',
                    `Expected window.osoosiDlp.releaseEvent to be a function in dashboard/${targetDirName}`
                );
                assert.strictEqual(
                    typeof env.mockWindow.osoosiDlp.releaseAllFalsePositives,
                    'function',
                    `Expected window.osoosiDlp.releaseAllFalsePositives to be a function in dashboard/${targetDirName}`
                );
                assert.strictEqual(
                    typeof env.mockWindow.osoosiDlp.refreshStatus,
                    'function',
                    `Expected window.osoosiDlp.refreshStatus to be a function in dashboard/${targetDirName}`
                );

                // 6. Auth resilience & zero Failed-to-fetch exports
                for (const authFn of ['sanitizeAuthNetworkError', 'authFetchWithFallback', 'activateLocalSessionFallback']) {
                    assert.strictEqual(
                        typeof env.mockWindow[authFn],
                        'function',
                        `Expected window.${authFn} to be a function in dashboard/${targetDirName}`
                    );
                }
                const sanitized = env.mockWindow.sanitizeAuthNetworkError('TypeError: Failed to fetch');
                assert.ok(!/failed to fetch/i.test(sanitized), 'sanitizeAuthNetworkError must never output Failed to fetch');

                // 7. Collapsible 7-Category Sidebar, CI/CD Protection & Collapsible Policy Detection Engines exports
                const expectedSidebarAndCicdMethods = [
                    'toggleSidebarRailMode',
                    'toggleAllSidebarCategories',
                    'filterSidebarMenu',
                    'expandSidebarCategoryForItem',
                    'initCollapsibleSidebar',
                    'renderCicdProtectionView',
                    'setCicdProtectionMaster',
                    'toggleCicdProtectionItem',
                    'toggleCicdProtectionAll',
                    'runCicdProtectionVerification',
                    'toggleEnginesPanel',
                    'togglePolicyEnginesCard',
                    'toggleDashboardPanel',
                    'toggleAllDashboardPanels',
                    'toggleEngineCategory',
                    'toggleAllEngineCategories',
                    'toggleSingleVoterCard',
                    'toggleAllVoterCardsCompact',
                    'renderEngines',
                    'toggleMitreOverviewPanel',
                    'toggleMitreFiltersPanel',
                    'toggleMitreTechniquesMatrixPanel',
                    'toggleMitreTacticCol',
                    'toggleAllMitreTactics',
                    'toggleMitreTechCard',
                    'toggleAllMitreTechCards',
                    'toggleCollapsiblePanel'
                ];
                for (const method of expectedSidebarAndCicdMethods) {
                    assert.strictEqual(
                        typeof env.mockWindow[method],
                        'function',
                        `Expected window.${method} to be a function in dashboard/${targetDirName}`
                    );
                }

                // 8. Verify Policy Detection Engines collapse state persists across renderEngines / renderDetectionStats polling
                env.mockWindow.renderEngines({});
                const gridEl = env.mockDocument.getElementById('detection-engines-grid');
                const bodyEl = env.mockDocument.getElementById('detection-engines-body');
                const btnEl = env.mockDocument.getElementById('toggle-engines-btn');
                assert.ok(gridEl.innerHTML.includes('data-engine-cat="ai-agentic"'), 'Must render AI, LLM & Agentic Security Voters category');
                assert.ok(gridEl.innerHTML.includes('data-engine-cat="memory-kernel"'), 'Must render Kernel, Memory & Binary Forensics Voters category');
                assert.ok(gridEl.innerHTML.includes('data-engine-cat="network-intel"'), 'Must render Threat Intelligence, C2 & CVE Voters category');
                assert.ok(gridEl.innerHTML.includes('data-engine-cat="physics-containment"'), 'Must render Behavioral Physics, Sigma & Containment Voters category');
                assert.ok(gridEl.innerHTML.includes('data-engine-cat="trust-reputation"'), 'Must render Zero-Trust Veto, Vendor & Noise Filter Voters category');

                // Collapse Policy Detection Engines
                env.mockWindow.togglePolicyEnginesCard();
                assert.strictEqual(env.mockWindow.localStorage.getItem('oshoosi_collapse_policy_engines'), 'true', 'oshoosi_collapse_policy_engines must be true when collapsed');
                assert.strictEqual(bodyEl.style.display, 'none', '#detection-engines-body must be hidden when collapsed');
                assert.strictEqual(gridEl.style.display, 'none', '#detection-engines-grid must be hidden when collapsed');
                assert.strictEqual(btnEl.textContent, 'Expand (39 Engines)', '#toggle-engines-btn must show Expand (39 Engines) when collapsed');

                // Simulate background poll re-rendering engines
                env.mockWindow.renderEngines({});
                assert.strictEqual(bodyEl.style.display, 'none', '#detection-engines-body must remain hidden after renderEngines poll');
                assert.strictEqual(gridEl.style.display, 'none', '#detection-engines-grid must remain hidden after renderEngines poll');
                assert.strictEqual(btnEl.textContent, 'Expand (39 Engines)', '#toggle-engines-btn must remain Expand (39 Engines) after renderEngines poll');

                // Expand back
                env.mockWindow.toggleEnginesPanel();
                assert.strictEqual(env.mockWindow.localStorage.getItem('oshoosi_collapse_policy_engines'), 'false', 'oshoosi_collapse_policy_engines must be false when expanded');
                assert.strictEqual(bodyEl.style.display, 'block', '#detection-engines-body must be visible when expanded');
                assert.strictEqual(gridEl.style.display, 'grid', '#detection-engines-grid must be grid when expanded');
                assert.strictEqual(btnEl.textContent, 'Collapse', '#toggle-engines-btn must show Collapse when expanded');
            });
        });
    });
});

// ============================================================================
// Suite 3: MITRE ATT&CK Matrix Layout Containment & Collapsible UI Verification
// ============================================================================
describe('MITRE ATT&CK Matrix Layout Containment & Collapsible UI Verification', () => {
    for (const targetDirName of ['src', 'dist']) {
        describe(`Target: dashboard/${targetDirName}`, () => {
            const targetDir = path.resolve(`dashboard/${targetDirName}`);

            it('should verify index.html MITRE container lacks width: max-content and includes collapse controls for every item', () => {
                const htmlContent = fs.readFileSync(path.join(targetDir, 'index.html'), 'utf8');

                assert.ok(!htmlContent.includes('width: max-content'),
                    'index.html must not contain width: max-content in MITRE matrix');

                assert.ok(htmlContent.includes('id="toggle-mitre-overview-btn"'), 'Must contain #toggle-mitre-overview-btn');
                assert.ok(htmlContent.includes('id="toggle-mitre-filters-btn"'), 'Must contain #toggle-mitre-filters-btn');
                assert.ok(htmlContent.includes('id="toggle-all-mitre-tactics-btn"'), 'Must contain #toggle-all-mitre-tactics-btn');
                assert.ok(htmlContent.includes('id="toggle-all-mitre-cards-btn"'), 'Must contain #toggle-all-mitre-cards-btn');
                assert.ok(htmlContent.includes('id="toggle-mitre-techniques-matrix-btn"'), 'Must contain #toggle-mitre-techniques-matrix-btn');
                assert.ok(htmlContent.includes('id="mitre-overview-body"'), 'Must contain #mitre-overview-body');
                assert.ok(htmlContent.includes('id="mitre-filters-body"'), 'Must contain #mitre-filters-body');
                assert.ok(htmlContent.includes('id="mitre-techniques-matrix-card"'), 'Must contain #mitre-techniques-matrix-card');
                assert.ok(htmlContent.includes('id="mitre-techniques-matrix-body"'), 'Must contain #mitre-techniques-matrix-body');
                assert.ok(htmlContent.includes('id="mitre-tactics-collapse-summary"'), 'Must contain #mitre-tactics-collapse-summary');
            });

            it('should verify style.css responsive multi-column grid and collapsible tactic/card styles', () => {
                const cssContent = fs.readFileSync(path.join(targetDir, 'style.css'), 'utf8');

                assert.ok(cssContent.includes('grid-template-columns: repeat(auto-fill, minmax(240px, 1fr))'),
                    '.mitre-matrix-container must use repeat(auto-fill, minmax(240px, 1fr))');
                assert.ok(cssContent.includes('.mitre-tactic-col.collapsed .mitre-techniques-list'),
                    'Must define .mitre-tactic-col.collapsed .mitre-techniques-list rule');
                assert.ok(cssContent.includes('.mitre-technique-card.collapsed .mitre-tech-body'),
                    'Must define .mitre-technique-card.collapsed .mitre-tech-body rule');
                assert.ok(cssContent.includes('display: none !important'),
                    'Collapsed MITRE rules must have display: none !important');
                assert.ok(cssContent.includes('.sidebar {') && cssContent.includes('flex-shrink: 0;'),
                    '.sidebar must have flex-shrink: 0');
                assert.ok(cssContent.includes('.content {') && cssContent.includes('min-width: 0;') && cssContent.includes('min-inline-size: 0;'),
                    '.content must enforce min-width: 0 and min-inline-size: 0');
            });

            it('should verify app.js exports MITRE collapse functions for Overview, Filters, Tactics, and Individual Technique Cards', () => {
                const appContent = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');

                assert.ok(appContent.includes('toggleMitreOverviewPanel'), 'Must include toggleMitreOverviewPanel');
                assert.ok(appContent.includes('toggleMitreFiltersPanel'), 'Must include toggleMitreFiltersPanel');
                assert.ok(appContent.includes('toggleMitreTechniquesMatrixPanel'), 'Must include toggleMitreTechniquesMatrixPanel');
                assert.ok(appContent.includes('toggleMitreTacticCol'), 'Must include toggleMitreTacticCol');
                assert.ok(appContent.includes('toggleAllMitreTactics'), 'Must include toggleAllMitreTactics');
                assert.ok(appContent.includes('toggleMitreTechCard'), 'Must include toggleMitreTechCard');
                assert.ok(appContent.includes('toggleAllMitreTechCards'), 'Must include toggleAllMitreTechCards');
                assert.ok(appContent.includes('updateMitreCollapseControlsUI'), 'Must include updateMitreCollapseControlsUI');
                assert.ok(appContent.includes('COLLAPSIBLE_PANELS'), 'Must include COLLAPSIBLE_PANELS');
                assert.ok(appContent.includes('toggleCollapsiblePanel'), 'Must include toggleCollapsiblePanel');
            });
        });
    }
});

// ============================================================================
// Suite 4: Research Swarm Verified Repos, Code Accordion & Steganography (F34-F37)
// ============================================================================
describe('Research Swarm Verified Repos, Code Accordion & Steganography (F34-F37)', () => {
    for (const targetDirName of ['src', 'dist']) {
        describe(`Target: dashboard/${targetDirName}`, () => {
            const targetDir = path.resolve(`dashboard/${targetDirName}`);

            it('should verify buildSafeRepoUrl blocks 404 fake repos and allows verified live repos', () => {
                const env = createBrowserEnvironment();
                const appCode = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');
                const script = new vm.Script(appCode, { filename: 'app.js' });
                const context = vm.createContext(env.mockWindow);
                script.runInContext(context);

                const buildSafeRepoUrl = env.mockWindow.buildSafeRepoUrl;
                assert.strictEqual(typeof buildSafeRepoUrl, 'function', 'buildSafeRepoUrl must be exported to window');

                // 404 repos must be blocked (return empty string)
                assert.strictEqual(buildSafeRepoUrl('https://github.com/AlignmentResearch/rlhf-poisoning-benchmark'), '', 'Must block rlhf-poisoning-benchmark');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/oshoosiclaw/mac-agent-bench'), '', 'Must block mac-agent-bench');

                // Live verified repos must be accepted
                assert.strictEqual(buildSafeRepoUrl('https://github.com/NVIDIA/garak'), 'https://github.com/NVIDIA/garak', 'Must accept NVIDIA/garak');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/ethz-spylab/agentdojo'), 'https://github.com/ethz-spylab/agentdojo', 'Must accept ethz-spylab/agentdojo');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/UKGovernmentBEIS/inspect_evals'), 'https://github.com/UKGovernmentBEIS/inspect_evals', 'Must accept inspect_evals');

                // Trailing punctuation stripping and fragment/query rejection
                assert.strictEqual(buildSafeRepoUrl('https://github.com/oyesanyf/OshoosiClaw).'), 'https://github.com/oyesanyf/OshoosiClaw', 'Must strip trailing paren and dot');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/oyesanyf/OshoosiClaw.'), 'https://github.com/oyesanyf/OshoosiClaw', 'Must strip trailing dot');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/oyesanyf/OshoosiClaw, '), 'https://github.com/oyesanyf/OshoosiClaw', 'Must strip trailing comma and space');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/oyesanyf/OshoosiClaw?query=1'), '', 'Must reject query params');
                assert.strictEqual(buildSafeRepoUrl('https://github.com/oyesanyf/OshoosiClaw#hash'), '', 'Must reject hash fragments');
            });

            it('should verify window._researchSwarmState has zero fake URLs and all rules have generated_code_snippet', () => {
                const env = createBrowserEnvironment();
                const appCode = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');
                const script = new vm.Script(appCode, { filename: 'app.js' });
                const context = vm.createContext(env.mockWindow);
                script.runInContext(context);

                const st = env.mockWindow._researchSwarmState;
                assert.ok(st, '_researchSwarmState must exist on window');
                assert.ok(Array.isArray(st.active_enforced_research_rules), 'active_enforced_research_rules must be an array');
                assert.strictEqual(st.active_enforced_research_rules.length, 4, 'Must contain 4 baseline rules');

                for (const rule of st.active_enforced_research_rules) {
                    assert.ok(!rule.code_repo_url.includes('rlhf-poisoning-benchmark'), `Rule ${rule.rule_id} must not contain rlhf-poisoning-benchmark`);
                    assert.ok(!rule.code_repo_url.includes('mac-agent-bench'), `Rule ${rule.rule_id} must not contain mac-agent-bench`);
                    assert.ok(rule.generated_code_snippet && rule.generated_code_snippet.length > 20, `Rule ${rule.rule_id} must have populated generated_code_snippet`);
                }

                // Verify specific live replacements
                const garakRule = st.active_enforced_research_rules.find(r => r.rule_id.includes('2406.11036') || r.rule_id.includes('2610.20437'));
                assert.ok(garakRule, 'Garak rule must exist');
                assert.strictEqual(garakRule.code_repo_url, 'https://github.com/NVIDIA/garak');

                const dojoRule = st.active_enforced_research_rules.find(r => r.rule_id.includes('2601.11893'));
                assert.ok(dojoRule, 'Rule 2601.11893 must exist');
                assert.strictEqual(dojoRule.code_repo_url, 'https://github.com/ethz-spylab/agentdojo');
            });

            it('should verify encodeCodeIntoImage and decodeCodeFromImage round-trip bit fidelity across RGB channels', async () => {
                const env = createBrowserEnvironment();
                const appCode = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');
                const script = new vm.Script(appCode, { filename: 'app.js' });
                const context = vm.createContext(env.mockWindow);
                script.runInContext(context);

                const encode = env.mockWindow.encodeCodeIntoImage;
                const decode = env.mockWindow.decodeCodeFromImage;
                assert.strictEqual(typeof encode, 'function', 'encodeCodeIntoImage must be exported');
                assert.strictEqual(typeof decode, 'function', 'decodeCodeFromImage must be exported');

                const secretPayload = new TextEncoder().encode('pub fn verify_defense_carrier() -> bool { true }');
                const imgData = await encode(secretPayload, 64, 64, null);

                assert.strictEqual(imgData.width, 64);
                assert.strictEqual(imgData.height, 64);
                assert.strictEqual(imgData.data.length, 64 * 64 * 4);

                // Verify all alpha channels remain 255 (skip alpha)
                for (let p = 0; p < 64 * 64; p++) {
                    assert.strictEqual(imgData.data[p * 4 + 3], 255, `Pixel ${p} alpha must remain 255`);
                }

                const decoded = await decode(imgData, null);
                const decodedText = new TextDecoder().decode(decoded);
                assert.strictEqual(decodedText, 'pub fn verify_defense_carrier() -> bool { true }', 'Decoded text must match original payload exactly');
            });

            it('should verify encodeCodeIntoImage and decodeCodeFromImage with Web Crypto AES-GCM encryption/decryption', async () => {
                const env = createBrowserEnvironment();
                const appCode = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');
                const script = new vm.Script(appCode, { filename: 'app.js' });
                const context = vm.createContext(env.mockWindow);
                script.runInContext(context);

                const encode = env.mockWindow.encodeCodeIntoImage;
                const decode = env.mockWindow.decodeCodeFromImage;

                const key = await env.mockWindow.crypto.subtle.generateKey(
                    { name: 'AES-GCM', length: 256 },
                    true,
                    ['encrypt', 'decrypt']
                );

                const secretPayload = new TextEncoder().encode('pub fn verify_crypto_guard() -> bool { true }');
                const imgData = await encode(secretPayload, 64, 64, key);
                const decrypted = await decode(imgData, key);
                const decryptedText = new TextDecoder().decode(decrypted);
                assert.strictEqual(decryptedText, 'pub fn verify_crypto_guard() -> bool { true }', 'AES-GCM decrypted payload must match original');
            });

            it('should verify renderEphemeralCodeToCanvas and scrubEphemeralCanvas memory zeroing lifecycle', async () => {
                const env = createBrowserEnvironment();
                const appCode = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');
                const script = new vm.Script(appCode, { filename: 'app.js' });
                const context = vm.createContext(env.mockWindow);
                script.runInContext(context);

                const render = env.mockWindow.renderEphemeralCodeToCanvas;
                const scrub = env.mockWindow.scrubEphemeralCanvas;
                const scrubAll = env.mockWindow.scrubAllEphemeralCanvases;

                assert.strictEqual(typeof render, 'function', 'renderEphemeralCodeToCanvas must be exported');
                assert.strictEqual(typeof scrub, 'function', 'scrubEphemeralCanvas must be exported');
                assert.strictEqual(typeof scrubAll, 'function', 'scrubAllEphemeralCanvases must be exported');

                const canvasId = 'stego-canvas-test-rule-1';
                const canvas = env.mockDocument.getElementById(canvasId);
                assert.ok(canvas, 'Canvas element must be created in document');

                const secretText = 'forbid(principal, action, resource) when { context.test == true };';
                const success = await render(canvasId, secretText);
                assert.ok(success, 'renderEphemeralCodeToCanvas must return true');

                // Inspect rendered pixel data
                const ctx = canvas.getContext('2d');
                assert.ok(ctx._imgData, 'Canvas 2d context must have image data');
                const nonZeroRendered = ctx._imgData.data.some(b => b > 0);
                assert.ok(nonZeroRendered, 'Rendered canvas must have non-zero pixel data');

                // Scrub the canvas
                scrub(canvasId);
                const allZeroAfterScrub = ctx._imgData.data.every(b => b === 0);
                assert.ok(allZeroAfterScrub, 'Canvas pixels must be zeroed after scrubEphemeralCanvas');
            });

            it('should verify renderResearchSwarmUI generates collapsible defense-code-accordion', () => {
                const env = createBrowserEnvironment();
                const appCode = fs.readFileSync(path.join(targetDir, 'app.js'), 'utf8');
                const script = new vm.Script(appCode, { filename: 'app.js' });
                const context = vm.createContext(env.mockWindow);
                script.runInContext(context);

                // Call renderResearchSwarmUI
                assert.strictEqual(typeof env.mockWindow.renderResearchSwarmUI, 'function', 'renderResearchSwarmUI must be function');
                env.mockWindow.renderResearchSwarmUI();

                const activeTbody = env.mockDocument.getElementById('research-active-rules-tbody');
                assert.ok(activeTbody, 'research-active-rules-tbody must exist');
                assert.ok(activeTbody.innerHTML.includes('defense-code-accordion'), 'HTML must contain defense-code-accordion');
                assert.ok(activeTbody.innerHTML.includes('cedar-policy-code'), 'HTML must contain cedar-policy-code');
                assert.ok(activeTbody.innerHTML.includes('rust-guard-code'), 'HTML must contain rust-guard-code');
                assert.ok(activeTbody.innerHTML.includes('btn-stego-render'), 'HTML must contain btn-stego-render');
                assert.ok(activeTbody.innerHTML.includes('stego-canvas-'), 'HTML must contain stego-canvas elements');
                assert.ok(activeTbody.innerHTML.includes('2024 (FOUNDATIONAL)'), 'HTML must contain 2024 (FOUNDATIONAL) badge for foundational papers');
                assert.ok(activeTbody.innerHTML.includes('2026+ (CURRENT)'), 'HTML must contain 2026+ (CURRENT) badge for frontier papers');
            });
        });
    }
});
