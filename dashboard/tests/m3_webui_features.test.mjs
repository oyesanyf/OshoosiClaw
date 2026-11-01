import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

describe('Milestone M3 WebUI Features: Env Gateway, SkyRL & Ollama Guidance', () => {
    const srcHtmlPath = path.resolve('dashboard/src/index.html');
    const distHtmlPath = path.resolve('dashboard/dist/index.html');
    const srcAppJsPath = path.resolve('dashboard/src/app.js');
    const distAppJsPath = path.resolve('dashboard/dist/app.js');
    const srcCssPath = path.resolve('dashboard/src/style.css');
    const distCssPath = path.resolve('dashboard/dist/style.css');

    const srcHtml = fs.readFileSync(srcHtmlPath, 'utf-8');
    const distHtml = fs.readFileSync(distHtmlPath, 'utf-8');
    const srcAppJs = fs.readFileSync(srcAppJsPath, 'utf-8');
    const distAppJs = fs.readFileSync(distAppJsPath, 'utf-8');
    const srcCss = fs.readFileSync(srcCssPath, 'utf-8');
    const distCss = fs.readFileSync(distCssPath, 'utf-8');

    it('should assert 0-diff parity between src and dist for all M3 files', () => {
        assert.strictEqual(srcHtml, distHtml, 'index.html must match byte-for-byte in src and dist');
        assert.strictEqual(srcAppJs, distAppJs, 'app.js must match byte-for-byte in src and dist');
        assert.strictEqual(srcCss, distCss, 'style.css must match byte-for-byte in src and dist');
    });

    describe('Feature 1: Environment Gateway & Secret Watcher Card in DOM', () => {
        const targets = [{ name: 'src', html: srcHtml }, { name: 'dist', html: distHtml }];

        for (const { name, html } of targets) {
            it(`[${name}] should verify #env-gateway-seal-card and core operational badges exist`, () => {
                assert.ok(html.includes('id="env-gateway-seal-card"'), 'Must contain #env-gateway-seal-card');
                assert.ok(html.includes('id="env-gateway-status-badge"'), 'Must contain #env-gateway-status-badge');
                assert.ok(html.includes('id="env-gateway-watcher-badge"'), 'Must contain #env-gateway-watcher-badge');
                assert.ok(html.includes('id="env-gateway-dacl-badge"'), 'Must contain #env-gateway-dacl-badge');
            });

            it(`[${name}] should verify all Environment Gateway action buttons and inputs exist`, () => {
                const requiredIds = [
                    'btn-scan-env-all-drives',
                    'btn-scan-env-workspace',
                    'btn-seal-env-secrets',
                    'btn-revert-env-secrets',
                    'btn-test-env-gateway',
                    'btn-save-env-config',
                    'env-config-watcher-enabled',
                    'env-config-auto-seal'
                ];
                for (const id of requiredIds) {
                    assert.ok(html.includes(`id="${id}"`), `Missing required element: ${id}`);
                }
            });

            it(`[${name}] should verify Magika table, Watcher feed, and 4-stage test panels exist`, () => {
                assert.ok(html.includes('id="env-scan-results-tbody"'), 'Must contain #env-scan-results-tbody');
                assert.ok(html.includes('id="env-watcher-events-tbody"'), 'Must contain #env-watcher-events-tbody');
                assert.ok(html.includes('id="env-gateway-test-results-panel"'), 'Must contain #env-gateway-test-results-panel');
                assert.ok(html.includes('id="env-gateway-test-results-body"'), 'Must contain #env-gateway-test-results-body');
            });
        }
    });

    describe('Feature 2: Dynamic Ollama Auto-Pull Card & Available Memory Law', () => {
        const targets = [{ name: 'src', html: srcHtml, app: srcAppJs }, { name: 'dist', html: distHtml, app: distAppJs }];

        for (const { name, html, app } of targets) {
            it(`[${name}] should verify #missing-model-guidance-card structure and terminal pill`, () => {
                assert.ok(html.includes('id="missing-model-guidance-card"'), 'Must contain #missing-model-guidance-card');
                assert.ok(html.includes('id="guidance-terminal-pill"'), 'Must contain #guidance-terminal-pill');
                assert.ok(html.includes('id="guidance-terminal-code"'), 'Must contain #guidance-terminal-code');
                assert.ok(html.includes('id="guidance-terminal-copy-btn"'), 'Must contain #guidance-terminal-copy-btn');
                assert.ok(html.includes('id="guidance-installed-pills"'), 'Must contain #guidance-installed-pills');
                assert.ok(html.includes('id="guidance-pull-retry-btn"'), 'Must contain #guidance-pull-retry-btn');
                assert.ok(html.includes('id="guidance-pull-bar"'), 'Must contain #guidance-pull-bar');
            });

            it(`[${name}] should verify Dynamic Available Memory Law sizing tiers in selectCalibratedQwenModel`, () => {
                const sandbox = {
                    window: {},
                    console,
                    setTimeout,
                    clearTimeout
                };
                vm.createContext(sandbox);

                const modelFnMatch = app.match(/function\s+selectCalibratedQwenModel\s*\([\s\S]*?\n\}/);
                const sanitizeFnMatch = app.match(/function\s+sanitizeOllamaModelTag\s*\([\s\S]*?\n\}/);
                assert.ok(modelFnMatch, 'selectCalibratedQwenModel must be defined');
                assert.ok(sanitizeFnMatch, 'sanitizeOllamaModelTag must be defined');

                vm.runInContext(`${sanitizeFnMatch[0]}; ${modelFnMatch[0]}; window.selectCalibratedQwenModel = selectCalibratedQwenModel;`, sandbox);

                // Tier 1: Free RAM >= 48GB or Free VRAM >= 24GB -> qwen2.5:32b
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 48, free_vram_mb: 0 }).model, 'qwen2.5:32b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel(48, 0).model, 'qwen2.5:32b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 8, free_vram_mb: 24576 }).model, 'qwen2.5:32b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel(8, 24576).model, 'qwen2.5:32b');

                // Tier 2: Free RAM >= 24GB or Free VRAM >= 14GB -> qwen2.5:14b
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 24, free_vram_mb: 0 }).model, 'qwen2.5:14b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel(24, 0).model, 'qwen2.5:14b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 8, free_vram_mb: 14336 }).model, 'qwen2.5:14b');

                // Tier 3: Free RAM >= 12GB or Free VRAM >= 4.5GB -> qwen2.5:7b
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 12, free_vram_mb: 0 }).model, 'qwen2.5:7b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel(12, 0).model, 'qwen2.5:7b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 8, free_vram_mb: 4608 }).model, 'qwen2.5:7b');

                // Tier 4: Free RAM >= 6GB or Free VRAM >= 2GB -> qwen2.5:3b
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 6, free_vram_mb: 0 }).model, 'qwen2.5:3b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel(6, 0).model, 'qwen2.5:3b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 4, free_vram_mb: 2048 }).model, 'qwen2.5:3b');

                // Tier 5: Free RAM < 6GB -> qwen2.5:1.5b
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 4, free_vram_mb: 1024 }).model, 'qwen2.5:1.5b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel(4, 1024).model, 'qwen2.5:1.5b');
                assert.strictEqual(sandbox.window.selectCalibratedQwenModel({ free_ram_gb: 2, free_vram_mb: 0 }).model, 'qwen2.5:1.5b');

                // Zero -coder suffix invariant
                const testCases = [
                    { free_ram_gb: 64, free_vram_mb: 32000 },
                    { free_ram_gb: 32, free_vram_mb: 16000 },
                    { free_ram_gb: 16, free_vram_mb: 8000 },
                    { free_ram_gb: 8, free_vram_mb: 3000 },
                    { free_ram_gb: 2, free_vram_mb: 500 }
                ];
                for (const tc of testCases) {
                    const res = sandbox.window.selectCalibratedQwenModel(tc);
                    assert.ok(!res.model.includes('-coder'), `Model '${res.model}' must never include -coder suffix`);
                }
            });

            it(`[${name}] should verify 400ms timeout in health probes`, () => {
                assert.ok(app.includes('fetchWithTimeout(`${cleanUrl}/api/tags`, { method: \'GET\' }, 400)'), 'probeOllama must enforce 400ms timeout');
                assert.ok(app.includes('fetchWithTimeout(endpoint, { method: \'GET\' }, 400)'), 'probeIpc must enforce 400ms timeout');
                assert.ok(app.includes('fetchWithTimeout(`http://127.0.0.1:${port}/json/version`, { method: \'GET\' }, 400)'), 'probeCdp must enforce 400ms timeout');
            });
        }
    });

    describe('Feature 3: SkyRL RL Mechanics & Zero-Mock Metrics Sync', () => {
        const targets = [{ name: 'src', html: srcHtml, app: srcAppJs }, { name: 'dist', html: distHtml, app: distAppJs }];

        for (const { name, html, app } of targets) {
            it(`[${name}] should verify state initializes zero mock arrays for skyrl histories`, () => {
                assert.ok(app.includes('skyrlLossHistory: []'), 'State must initialize empty skyrlLossHistory');
                assert.ok(app.includes('skyrlRewardHistory: []'), 'State must initialize empty skyrlRewardHistory');
                assert.ok(app.includes('skyrlLabels: []'), 'State must initialize empty skyrlLabels');
                assert.ok(!app.includes('skyrlLossHistory: [0.85'), 'Must not contain hardcoded mock loss history in state');
            });

            it(`[${name}] should verify SkyRL DOM elements exist under #skyrl-view`, () => {
                const skyrlIds = [
                    'skyrl-phase-header-badge',
                    'stat-skyrl-step-target',
                    'stat-skyrl-warmup-badge',
                    'stat-skyrl-phase',
                    'stat-skyrl-epsilon-bar',
                    'skyrl-loss-latest-badge',
                    'skyrl-reward-latest-badge'
                ];
                for (const id of skyrlIds) {
                    assert.ok(html.includes(`id="${id}"`), `Missing required SkyRL DOM element: ${id}`);
                }
            });

            it(`[${name}] should verify linear epsilon decay and phase calculation logic`, () => {
                assert.ok(app.includes('epsStart > epsMin'), 'Must check epsStart > epsMin for decay calculation');
                assert.ok(app.includes('(epsStart - currentEps) / (epsStart - epsMin)'), 'Must calculate linear decay fraction');
                assert.ok(app.includes('rawPhase === \'warming_up\''), 'Must handle warming_up phase');
                assert.ok(app.includes('rawPhase === \'converged_exploitation\''), 'Must handle converged_exploitation phase');
            });
        }
    });

    describe('Feature 4: Global Function Exports on Window', () => {
        const targets = [{ name: 'src', app: srcAppJs }, { name: 'dist', app: distAppJs }];

        for (const { name, app } of targets) {
            it(`[${name}] should export all required M3 functions on window object`, () => {
                const requiredExports = [
                    'loadEnvGatewayStatus',
                    'loadEnvGatewayConfig',
                    'saveEnvGatewayConfig',
                    'scanEnvFiles',
                    'filterEnvScanResults',
                    'sealEnvSecrets',
                    'sealSingleEnvFile',
                    'revertEnvSecrets',
                    'revertSingleEnvFile',
                    'toggleEnvWatcher',
                    'updateEnvWatcherAutoSeal',
                    'pollEnvWatcherEvents',
                    'testEnvGateway',
                    'triggerMissingModelAutoPull',
                    'selectGuidanceAlternativeModel',
                    'retryGuidanceModelPull',
                    'selectCalibratedQwenModel',
                    'sanitizeOllamaModelTag',
                    'initSkyrlCharts',
                    'updateSkyrlCharts',
                    'updateSkyrlStats'
                ];

                for (const exp of requiredExports) {
                    assert.ok(
                        app.includes(`window.${exp} = ${exp}`) || app.includes(`window.${exp} =`),
                        `window.${exp} must be exported`
                    );
                }
            });
        }
    });
});
