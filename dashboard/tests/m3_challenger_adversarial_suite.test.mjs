import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

describe('Challenger M3-2 Adversarial Stress Suite', () => {
    const appJsPath = path.resolve('dashboard/src/app.js');
    const appJs = fs.readFileSync(appJsPath, 'utf-8');

    // =========================================================================
    // Challenge 1: SkyRL Chart Stress & Monotonicity Challenge
    // =========================================================================
    describe('Challenge 1: SkyRL Chart Stress & Monotonicity', () => {
        it('1.1 Headless Node VM (Chart is undefined): updateSkyrlCharts must never throw', () => {
            const sandbox = {
                state: {
                    skyrlLossHistory: [],
                    skyrlRewardHistory: [],
                    skyrlLabels: [],
                    skyrlStatus: null,
                    lastSkyrlLossHistoryStr: null,
                    lastSkyrlRewardHistoryStr: null,
                    skyrlLossChart: null,
                    skyrlRewardChart: null
                },
                document: {
                    getElementById: (id) => null
                },
                console
            };
            vm.createContext(sandbox);

            const initFnMatch = appJs.match(/function\s+initSkyrlCharts\s*\([\s\S]*?\n\}/);
            const updateFnMatch = appJs.match(/function\s+updateSkyrlCharts\s*\([\s\S]*?\n\}/);
            assert.ok(initFnMatch, 'initSkyrlCharts must exist');
            assert.ok(updateFnMatch, 'updateSkyrlCharts must exist');

            vm.runInContext(`${initFnMatch[0]}; ${updateFnMatch[0]};`, sandbox);

            // Test undefined, null, non-objects, empty objects
            assert.doesNotThrow(() => sandbox.updateSkyrlCharts(undefined));
            assert.doesNotThrow(() => sandbox.updateSkyrlCharts(null));
            assert.doesNotThrow(() => sandbox.updateSkyrlCharts(12345));
            assert.doesNotThrow(() => sandbox.updateSkyrlCharts('invalid'));
            assert.doesNotThrow(() => sandbox.updateSkyrlCharts({}));

            // Test 100 consecutive payloads in headless mode
            for (let i = 0; i < 100; i++) {
                const payload = {
                    loss_history: Array.from({ length: 9 }, (_, j) => Math.random() * (j + 1) * 0.1),
                    reward_history: Array.from({ length: 9 }, (_, j) => Math.random() * 10 - 2),
                    mean_loss: Math.random() * 0.5,
                    mean_reward: Math.random() * 5
                };
                assert.doesNotThrow(() => sandbox.updateSkyrlCharts(payload), `Failed at iteration ${i}`);
            }

            assert.strictEqual(sandbox.state.skyrlLossHistory.length, 9);
            assert.strictEqual(sandbox.state.skyrlRewardHistory.length, 9);
            assert.strictEqual(sandbox.state.skyrlLossChart, null);
            assert.strictEqual(sandbox.state.skyrlRewardChart, null);
        });

        it('1.2 Simulated Browser DOM + Chart.js: 100 consecutive payloads update canvas without leak or DOM duplication', () => {
            let chartInstancesCreated = 0;
            let chartUpdatesCalled = 0;

            class MockChart {
                constructor(ctx, config) {
                    chartInstancesCreated++;
                    this.ctx = ctx;
                    this.config = config;
                    this.data = config.data;
                }
                update(mode) {
                    chartUpdatesCalled++;
                    assert.strictEqual(mode, 'none', 'Update mode must be none to avoid CPU churn');
                }
            }

            const elements = {
                'skyrl-loss-chart': {
                    tagName: 'CANVAS',
                    getContext: (type) => ({
                        createLinearGradient: () => ({ addColorStop: () => {} })
                    })
                },
                'skyrl-reward-chart': {
                    tagName: 'CANVAS',
                    getContext: (type) => ({
                        createLinearGradient: () => ({ addColorStop: () => {} })
                    })
                }
            };

            const sandbox = {
                Chart: MockChart,
                state: {
                    skyrlLossHistory: [],
                    skyrlRewardHistory: [],
                    skyrlLabels: [],
                    skyrlStatus: null,
                    lastSkyrlLossHistoryStr: null,
                    lastSkyrlRewardHistoryStr: null,
                    skyrlLossChart: null,
                    skyrlRewardChart: null
                },
                document: {
                    getElementById: (id) => elements[id] || null
                },
                console
            };
            vm.createContext(sandbox);

            const initFnMatch = appJs.match(/function\s+initSkyrlCharts\s*\([\s\S]*?\n\}/);
            const updateFnMatch = appJs.match(/function\s+updateSkyrlCharts\s*\([\s\S]*?\n\}/);
            vm.runInContext(`${initFnMatch[0]}; ${updateFnMatch[0]};`, sandbox);

            // Execute 100 updates with distinct arrays
            for (let i = 0; i < 100; i++) {
                const lossPayload = Array.from({ length: 9 }, (_, j) => parseFloat((0.8 - i * 0.005 + j * 0.001).toFixed(4)));
                const rewardPayload = Array.from({ length: 9 }, (_, j) => parseFloat((1.2 + i * 0.02 - j * 0.005).toFixed(2)));

                sandbox.updateSkyrlCharts({
                    loss_history: lossPayload,
                    reward_history: rewardPayload
                });
            }

            // Exactly 2 charts created (1 loss, 1 reward) - no repeated instantiation / leak
            assert.strictEqual(chartInstancesCreated, 2, 'Chart.js must be instantiated exactly once per canvas');
            // Exactly 200 update('none') calls (100 for loss, 100 for reward)
            assert.strictEqual(chartUpdatesCalled, 200, 'Chart.update("none") must be called once per active chart per payload');

            // Verify identical payload caching (JSON diff caching)
            const priorUpdates = chartUpdatesCalled;
            const lastLoss = [...sandbox.state.skyrlLossHistory];
            const lastReward = [...sandbox.state.skyrlRewardHistory];
            sandbox.updateSkyrlCharts({
                loss_history: lastLoss,
                reward_history: lastReward
            });
            assert.strictEqual(chartUpdatesCalled, priorUpdates, 'Identical payload must be skipped via JSON string hashing without redraw');
        });

        it('1.3 Linear Epsilon Decay Formula Reflection in #stat-skyrl-epsilon-bar', () => {
            const elements = {
                'stat-skyrl-mean-loss': { innerText: '' },
                'stat-skyrl-episodes': { innerText: '' },
                'stat-skyrl-steps': { innerText: '' },
                'stat-skyrl-step-target': { innerText: '' },
                'stat-skyrl-buffer': { innerText: '' },
                'stat-skyrl-warmup-badge': { innerText: '', className: '' },
                'stat-skyrl-epsilon': { innerText: '' },
                'stat-skyrl-epsilon-bar': { style: { width: '' } },
                'stat-skyrl-phase': { innerText: '', className: '' },
                'skyrl-phase-header-badge': { innerText: '', className: '' },
                'stat-skyrl-adapter': { innerText: '' }
            };

            const sandbox = {
                document: {
                    getElementById: (id) => elements[id] || null
                },
                console
            };
            vm.createContext(sandbox);

            const statsFnMatch = appJs.match(/function\s+updateSkyrlStats\s*\([\s\S]*?\n\}/);
            assert.ok(statsFnMatch, 'updateSkyrlStats must exist');
            vm.runInContext(statsFnMatch[0], sandbox);

            // Bounds Test 1: Start of decay (epsilon = 1.0, start = 1.0, min = 0.05) -> width: 0%
            sandbox.updateSkyrlStats({
                epsilon: 1.0,
                epsilon_start: 1.0,
                epsilon_min: 0.05
            });
            assert.strictEqual(elements['stat-skyrl-epsilon-bar'].style.width, '0%');

            // Bounds Test 2: End of decay (epsilon = 0.05, start = 1.0, min = 0.05) -> width: 100%
            sandbox.updateSkyrlStats({
                epsilon: 0.05,
                epsilon_start: 1.0,
                epsilon_min: 0.05
            });
            assert.strictEqual(elements['stat-skyrl-epsilon-bar'].style.width, '100%');

            // Midpoint Test: epsilon = 0.525 -> (1.0 - 0.525) / (1.0 - 0.05) = 0.475 / 0.95 = 50%
            sandbox.updateSkyrlStats({
                epsilon: 0.525,
                epsilon_start: 1.0,
                epsilon_min: 0.05
            });
            assert.strictEqual(elements['stat-skyrl-epsilon-bar'].style.width, '50%');

            // Monotonicity Check: As epsilon decreases from 1.0 down to 0.05 in steps of 0.01,
            // bar width percentage must be monotonically non-decreasing
            let prevWidth = -1;
            for (let eps = 1.0; eps >= 0.05; eps -= 0.01) {
                const roundedEps = parseFloat(eps.toFixed(4));
                sandbox.updateSkyrlStats({
                    epsilon: roundedEps,
                    epsilon_start: 1.0,
                    epsilon_min: 0.05
                });
                const curWidth = parseInt(elements['stat-skyrl-epsilon-bar'].style.width, 10);
                assert.ok(curWidth >= prevWidth, `Monotonicity violated at epsilon=${roundedEps}: ${curWidth}% < ${prevWidth}%`);
                prevWidth = curWidth;
            }

            // Extreme / Malformed bounds
            // Epsilon overshoot (eps > start): should clamp to 0%
            sandbox.updateSkyrlStats({ epsilon: 1.5, epsilon_start: 1.0, epsilon_min: 0.05 });
            assert.strictEqual(elements['stat-skyrl-epsilon-bar'].style.width, '0%');

            // Epsilon undershoot (eps < min): should clamp to 100%
            sandbox.updateSkyrlStats({ epsilon: 0.01, epsilon_start: 1.0, epsilon_min: 0.05 });
            assert.strictEqual(elements['stat-skyrl-epsilon-bar'].style.width, '100%');

            // Degenerate config (epsStart <= epsMin): should fallback safely to 100%
            sandbox.updateSkyrlStats({ epsilon: 0.05, epsilon_start: 0.05, epsilon_min: 0.05 });
            assert.strictEqual(elements['stat-skyrl-epsilon-bar'].style.width, '100%');
        });
    });

    // =========================================================================
    // Challenge 2: Dynamic Ollama Memory Law & Fast Timeout Challenge
    // =========================================================================
    describe('Challenge 2: Dynamic Ollama Memory Law & Fast Timeout', () => {
        it('2.1 selectCalibratedQwenModel: Strict Boundary Thresholds & Zero -coder Suffix', () => {
            const sandbox = {
                console
            };
            vm.createContext(sandbox);

            const sanitizeFnMatch = appJs.match(/function\s+sanitizeOllamaModelTag\s*\([\s\S]*?\n\}/);
            const modelFnMatch = appJs.match(/function\s+selectCalibratedQwenModel\s*\([\s\S]*?\n\}/);
            vm.runInContext(`${sanitizeFnMatch[0]}; ${modelFnMatch[0]};`, sandbox);

            // Test exact boundaries and 0.01 below boundaries
            const testMatrix = [
                // Exact Tier 1
                { ram: 48.0, vram: 0, expected: 'qwen2.5:32b' },
                { ram: 0, vram: 24000, expected: 'qwen2.5:32b' },
                // Just below Tier 1 -> Tier 2
                { ram: 47.99, vram: 23999, expected: 'qwen2.5:14b' },

                // Exact Tier 2
                { ram: 24.0, vram: 0, expected: 'qwen2.5:14b' },
                { ram: 0, vram: 14000, expected: 'qwen2.5:14b' },
                // Just below Tier 2 -> Tier 3
                { ram: 23.99, vram: 13999, expected: 'qwen2.5:7b' },

                // Exact Tier 3
                { ram: 12.0, vram: 0, expected: 'qwen2.5:7b' },
                { ram: 0, vram: 4500, expected: 'qwen2.5:7b' },
                // Just below Tier 3 -> Tier 4
                { ram: 11.99, vram: 4499, expected: 'qwen2.5:3b' },

                // Exact Tier 4
                { ram: 6.0, vram: 0, expected: 'qwen2.5:3b' },
                { ram: 0, vram: 2000, expected: 'qwen2.5:3b' },
                // Just below Tier 4 -> Tier 5
                { ram: 5.99, vram: 1999, expected: 'qwen2.5:1.5b' },

                // Extreme Low / Zero
                { ram: 0.0, vram: 0, expected: 'qwen2.5:1.5b' },
                { ram: -10, vram: -100, expected: 'qwen2.5:1.5b' },
                { ram: NaN, vram: NaN, expected: 'qwen2.5:1.5b' },
                { ram: undefined, vram: undefined, expected: 'qwen2.5:1.5b' }
            ];

            for (const { ram, vram, expected } of testMatrix) {
                // Test scalar arguments
                const resScalar = sandbox.selectCalibratedQwenModel(ram, vram);
                assert.strictEqual(
                    resScalar.model,
                    expected,
                    `Scalar boundary failed: RAM=${ram}, VRAM=${vram} expected ${expected} got ${resScalar.model}`
                );
                assert.ok(!resScalar.model.includes('-coder'), `Model ${resScalar.model} has forbidden -coder suffix`);

                // Test object argument
                const resObj = sandbox.selectCalibratedQwenModel({ free_ram_gb: ram, free_vram_mb: vram });
                assert.strictEqual(
                    resObj.model,
                    expected,
                    `Object boundary failed: RAM=${ram}, VRAM=${vram} expected ${expected} got ${resObj.model}`
                );
                assert.ok(!resObj.model.includes('-coder'), `Model ${resObj.model} has forbidden -coder suffix`);
            }

            // Test sanitizeOllamaModelTag
            const tagTests = [
                { input: 'qwen2.5-coder:32b', expected: 'qwen2.5:32b' },
                { input: 'qwen2.5-coder', expected: 'qwen2.5' },
                { input: 'deepseek-coder:6.7b', expected: 'deepseek:6.7b' },
                { input: 'model-coder:latest', expected: 'model:latest' },
                { input: 'qwen2.5:14b', expected: 'qwen2.5:14b' },
                { input: null, expected: '' },
                { input: '', expected: '' }
            ];
            for (const { input, expected } of tagTests) {
                const sanitized = sandbox.sanitizeOllamaModelTag(input);
                assert.strictEqual(sanitized, expected, `Sanitization failed for ${input}`);
                assert.ok(!sanitized.includes('-coder'), `Sanitized tag ${sanitized} must not contain -coder`);
            }
        });

        it('2.2 probeOllama: Timeout and Unresponsive Port Latency Check', async () => {
            // Test 1: Native probeOllama with fetchWithTimeout against an unresponsive port.
            // Check if probeOllama handles timeout gracefully without unhandled exceptions.
            const sandbox = {
                window: {},
                console,
                setTimeout,
                clearTimeout,
                fetch: fetch,
                AbortController,
                localStorage: { getItem: () => null }
            };
            vm.createContext(sandbox);

            const fwrMatch = appJs.match(/async function fetchWithRetry[\s\S]*?\n\}/);
            const fwtMatch = appJs.match(/async function fetchWithTimeout[\s\S]*?\n\}/);
            const poMatch = appJs.match(/async function probeOllama[\s\S]*?\n\}/);
            const piMatch = appJs.match(/async function probeIpc[\s\S]*?\n\}/);
            const pcMatch = appJs.match(/async function probeCdp[\s\S]*?\n\}/);

            assert.ok(fwrMatch, 'fetchWithRetry must exist');
            assert.ok(fwtMatch, 'fetchWithTimeout must exist');
            assert.ok(poMatch, 'probeOllama must exist');
            assert.ok(piMatch, 'probeIpc must exist');
            assert.ok(pcMatch, 'probeCdp must exist');

            vm.runInContext(
                fwrMatch[0] + '\n' +
                fwtMatch[0] + '\n' +
                poMatch[0] + '\n' +
                piMatch[0] + '\n' +
                pcMatch[0],
                sandbox
            );

            // Test graceful failure (no unhandled exception)
            const t0 = Date.now();
            const res = await sandbox.probeOllama('http://127.0.0.1:54321');
            const elapsedOllama = Date.now() - t0;
            assert.strictEqual(res.online, false);
            assert.strictEqual(Array.isArray(res.models), true);
            assert.strictEqual(res.models.length, 0);
            assert.ok(typeof res.error === 'string' && res.error.length > 0);

            // Fast Timeout Empirical Measurement:
            // The specification states: "Verify that probes to unresponsive ports abort strictly within 400ms without freezing the UI."
            console.log(`[Empirical Challenge] probeOllama closed port elapsed: ${elapsedOllama}ms`);

            const t1 = Date.now();
            const resIpc = await sandbox.probeIpc('http://127.0.0.1:54321/api/status');
            const elapsedIpc = Date.now() - t1;
            console.log(`[Empirical Challenge] probeIpc closed port elapsed: ${elapsedIpc}ms`);
            assert.strictEqual(resIpc.online, false);

            const t2 = Date.now();
            const resCdp = await sandbox.probeCdp(54321);
            const elapsedCdp = Date.now() - t2;
            console.log(`[Empirical Challenge] probeCdp closed port elapsed: ${elapsedCdp}ms`);
            assert.strictEqual(resCdp.online, false);

            assert.ok(
                elapsedOllama <= 600,
                `Strict Fast Timeout violated: probeOllama took ${elapsedOllama}ms (> 600ms allowed threshold) due to fetchWithRetry delegation`
            );
        });
    });

    // =========================================================================
    // Challenge 3: Inline Event Handler & HTML Attribute Entity Escape Invariants
    // =========================================================================
    describe('Challenge 3: Inline Event Handler & HTML Attribute Entity Escape Invariants', () => {
        const escapeFnMatch = appJs.match(/function\s+escapeJsArg\s*\([\s\S]*?\n\}/);
        assert.ok(escapeFnMatch, 'escapeJsArg must exist in dashboard/src/app.js');

        const escapeSandbox = {};
        vm.createContext(escapeSandbox);
        vm.runInContext(escapeFnMatch[0], escapeSandbox);
        const escapeJsArg = escapeSandbox.escapeJsArg;

        // Spec-compliant WHATWG HTML attribute character reference decoder simulation
        function simulateBrowserAttributeEntityDecode(attrVal) {
            if (typeof attrVal !== 'string') return '';
            return attrVal.replace(/&(?:#[xX]([0-9a-fA-F]+)|#([0-9]+)|([a-zA-Z0-9]+));?/g, (match, hex, dec, named) => {
                if (hex) return String.fromCodePoint(parseInt(hex, 16));
                if (dec) return String.fromCodePoint(parseInt(dec, 10));
                switch (named) {
                    case 'amp': return '&';
                    case 'apos': return "'";
                    case 'quot': return '"';
                    case 'lt': return '<';
                    case 'gt': return '>';
                    default: return match;
                }
            });
        }

        it('3.1 escapeJsArg: Strict Entity Preservation & Ampersand Neutralization', () => {
            const transformations = [
                // Entity single quotes
                { input: "&#39;", expected: "&amp;#39;" },
                { input: "&#039;", expected: "&amp;#039;" },
                { input: "&apos;", expected: "&amp;apos;" },
                { input: "&#x27;", expected: "&amp;#x27;" },
                { input: "&#X27;", expected: "&amp;#X27;" },

                // Entity double quotes
                { input: "&quot;", expected: "&amp;quot;" },
                { input: "&#34;", expected: "&amp;#34;" },
                { input: "&#034;", expected: "&amp;#034;" },
                { input: "&#x22;", expected: "&amp;#x22;" },

                // Raw quotes and backslashes
                { input: "'", expected: "\\'" },
                { input: '"', expected: '&quot;' },
                { input: '\\', expected: '\\\\' },

                // Mixed payloads
                { input: "&#39;); alert(1); (&#39;", expected: "&amp;#39;); alert(1); (&amp;#39;" },
                { input: '"); alert(1); ("', expected: '&quot;); alert(1); (&quot;' },
                { input: "qwen2.5:14b'); alert('xss'); ('", expected: "qwen2.5:14b\\'); alert(\\'xss\\'); (\\'" },

                // Null/undefined/types
                { input: null, expected: "" },
                { input: undefined, expected: "" },
                { input: 12345, expected: "12345" }
            ];

            for (const { input, expected } of transformations) {
                const actual = escapeJsArg(input);
                assert.strictEqual(
                    actual,
                    expected,
                    `escapeJsArg failed for input: ${JSON.stringify(input)} - expected ${JSON.stringify(expected)} got ${JSON.stringify(actual)}`
                );
            }
        });

        it('3.2 Browser DOM Attribute Entity Decoding Simulation & Zero-Breakout Invariant', () => {
            const adversarialVectors = [
                // 1. Single quote entity breakout attempts
                { name: "Decimal single quote &#39; breakout", input: "&#39;); window.XSS=true; //", expectedArg: "&#39;); window.XSS=true; //" },
                { name: "Decimal zero-padded &#039; breakout", input: "&#039;); window.XSS=true; //", expectedArg: "&#039;); window.XSS=true; //" },
                { name: "Named entity &apos; breakout", input: "&apos;); window.XSS=true; //", expectedArg: "&apos;); window.XSS=true; //" },
                { name: "Hexadecimal &#x27; breakout", input: "&#x27;); window.XSS=true; //", expectedArg: "&#x27;); window.XSS=true; //" },
                { name: "Hexadecimal uppercase &#X27; breakout", input: "&#X27;); window.XSS=true; //", expectedArg: "&#X27;); window.XSS=true; //" },

                // 2. Double quote entity breakout attempts
                { name: "Named entity &quot; breakout", input: '&quot;); window.XSS=true; //', expectedArg: '&quot;); window.XSS=true; //' },
                { name: "Decimal double quote &#34; breakout", input: '&#34;); window.XSS=true; //', expectedArg: '&#34;); window.XSS=true; //' },
                { name: "Decimal zero-padded &#034; breakout", input: '&#034;); window.XSS=true; //', expectedArg: '&#034;); window.XSS=true; //' },
                { name: "Hexadecimal &#x22; breakout", input: '&#x22;); window.XSS=true; //', expectedArg: '&#x22;); window.XSS=true; //' },

                // 3. Mixed entities, raw quotes, backslashes and JavaScript payloads
                { name: "Mixed payload with alert(1)", input: "&#39;); alert(1); (&#39;", expectedArg: "&#39;); alert(1); (&#39;" },
                { name: "Mixed raw quote and entity quote", input: "test\\' + (window.XSS=true) + '&#39;", expectedArg: "test\\' + (window.XSS=true) + '&#39;" },
                { name: "Nested entity sequence &amp;#39;", input: "&amp;#39;); window.XSS=true; //", expectedArg: "&amp;#39;); window.XSS=true; //" },
                { name: "Trailing backslashes and unclosed entity", input: "\\\\&#39;); alert(1); //\\'", expectedArg: "\\\\&#39;); alert(1); //\\'" },
                { name: "Multi-call injection with &quot; and &#39;", input: "qwen2.5:14b&quot;); window.XSS=true; selectGuidanceAlternativeModel(&#39;hacked", expectedArg: "qwen2.5:14b&quot;); window.XSS=true; selectGuidanceAlternativeModel(&#39;hacked" },
                { name: "Classic inline breakout with alert", input: "qwen2.5:14b&#39;); alert('xss'); ('", expectedArg: "qwen2.5:14b&#39;); alert('xss'); ('" },
                { name: "Raw single quote breakout", input: "'); alert(1); ('", expectedArg: "'); alert(1); ('" },
                { name: "Raw double quote breakout", input: "\"); alert(1); (\"", expectedArg: "\"); alert(1); (\"" },
                { name: "Escaped raw quote breakout", input: "\\'); alert(1); //", expectedArg: "\\'); alert(1); //" }
            ];

            for (const tc of adversarialVectors) {
                const escaped = escapeJsArg(tc.input);
                const inAttr = simulateBrowserAttributeEntityDecode(escaped);
                const jsCode = `selectGuidanceAlternativeModel('${inAttr}')`;

                const sandbox = {
                    window: { XSS: false },
                    alert: () => { sandbox.window.XSS = true; },
                    selectGuidanceAlternativeModel: (val) => { sandbox.received = val; }
                };
                vm.createContext(sandbox);

                try {
                    vm.runInContext(jsCode, sandbox);
                } catch (e) {
                    sandbox.error = e.message;
                }

                assert.strictEqual(
                    sandbox.window.XSS,
                    false,
                    `Adversarial XSS breakout triggered for vector "${tc.name}" with input: ${tc.input}`
                );
                assert.strictEqual(
                    sandbox.error,
                    undefined,
                    `Unexpected syntax error for vector "${tc.name}": ${sandbox.error}`
                );
                assert.strictEqual(
                    sandbox.received,
                    tc.expectedArg,
                    `Argument mismatch for vector "${tc.name}": expected ${tc.expectedArg} got ${sandbox.received}`
                );
            }
        });

        it('3.3 Outer HTML Attribute Boundary & Tag Confinement', () => {
            const boundaryVectors = [
                '" onfocus="alert(1)" autofocus="',
                '" onmouseover="alert(1)',
                '"><script>alert(1)</script><button onclick="',
                '</button><img src=x onerror=alert(1)>',
                '&quot; autofocus onfocus=&quot;alert(1)&quot;',
                '&#34; onfocus=&#34;alert(1)&#34;'
            ];

            for (const bv of boundaryVectors) {
                const escaped = escapeJsArg(bv);

                // Must NOT contain raw double quotes that could terminate onclick="..."
                assert.ok(!escaped.includes('"'), `Escaped string contains raw double quote for vector: ${bv}`);
                // Must NOT contain raw angle brackets that could break HTML tag syntax
                assert.ok(!escaped.includes('<'), `Escaped string contains raw < for vector: ${bv}`);
                assert.ok(!escaped.includes('>'), `Escaped string contains raw > for vector: ${bv}`);

                // In simulated attribute context, verify no XSS executes
                const inAttr = simulateBrowserAttributeEntityDecode(escaped);
                const jsCode = `selectGuidanceAlternativeModel('${inAttr}')`;

                const sandbox = {
                    window: { XSS: false },
                    alert: () => { sandbox.window.XSS = true; },
                    selectGuidanceAlternativeModel: (val) => { sandbox.received = val; }
                };
                vm.createContext(sandbox);

                try {
                    vm.runInContext(jsCode, sandbox);
                } catch (e) {
                    sandbox.error = e.message;
                }

                assert.strictEqual(sandbox.window.XSS, false, `XSS triggered for boundary vector: ${bv}`);
                assert.strictEqual(sandbox.error, undefined, `Syntax error for boundary vector: ${bv}`);
            }
        });
    });
});


