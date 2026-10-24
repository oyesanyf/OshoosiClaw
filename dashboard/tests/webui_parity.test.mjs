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

        const elementRegistry = {};
        const mockDocument = {
            readyState: 'loading',
            body: mockElement('body'),
            getElementById(id) {
                if (!elementRegistry[id]) {
                    elementRegistry[id] = mockElement(id);
                }
                return elementRegistry[id];
            },
            querySelector(sel) {
                if (sel && sel.startsWith('#')) {
                    const id = sel.slice(1);
                    if (!elementRegistry[id]) {
                        elementRegistry[id] = mockElement(id);
                    }
                    return elementRegistry[id];
                }
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
