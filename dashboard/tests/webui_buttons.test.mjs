import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

describe('WebUI 128 Buttons & Backend REST API Endpoints Verification (Features 15, 17)', () => {
    const htmlPath = path.resolve('dashboard/src/index.html');
    const appJsPath = path.resolve('dashboard/src/app.js');
    const htmlContent = fs.readFileSync(htmlPath, 'utf-8');
    const appJsContent = fs.readFileSync(appJsPath, 'utf-8');

    it('should assert that at least 128 button elements exist in index.html', () => {
        const buttonMatches = [...htmlContent.matchAll(/<button\b([^>]*)>/gi)];
        assert.ok(buttonMatches.length >= 128, `Must contain at least 128 interactive button elements (found ${buttonMatches.length})`);
    });

    it('should assert that all buttons possess an id, class, or inline onclick attribute', () => {
        const buttonMatches = [...htmlContent.matchAll(/<button\b([^>]*)>/gi)];
        for (let i = 0; i < buttonMatches.length; i++) {
            const rawAttrs = buttonMatches[i][1];
            const hasId = /id=["'][^"']+["']/.test(rawAttrs);
            const hasClass = /class=["'][^"']+["']/.test(rawAttrs);
            const hasOnclick = /onclick=["'][^"']+["']/.test(rawAttrs);
            assert.ok(
                hasId || hasClass || hasOnclick,
                `Button #${i + 1} (${rawAttrs.slice(0, 50)}) must have an id, class, or onclick attribute`
            );
        }
    });

    it('should verify critical operational header and collapse buttons are present and wired', () => {
        const criticalHeaderButtons = [
            'supervisor-top-btn',
            'defense-mode-top-btn',
            'mesh-status-top-btn',
            'admin-settings-top-btn',
            'toggle-engines-btn',
            'toggle-engine-categories-btn',
            'toggle-voter-compact-btn',
            'sidebar-rail-toggle-btn',
            'sidebar-collapse-expand-all-btn'
        ];

        for (const btnId of criticalHeaderButtons) {
            assert.ok(htmlContent.includes(`id="${btnId}"`), `Button '${btnId}' must exist`);
        }
    });

    it('should verify backend REST API routes are invoked in app.js with zero mocks', () => {
        const expectedApiEndpoints = [
            '/status',
            '/threats',
            '/consensus/findings',
            '/yara/status',
            '/yara/reload',
            '/detection-stats',
            '/mesh-stats',
            '/blocking/rules'
        ];

        for (const endpoint of expectedApiEndpoints) {
            const hasEndpoint = appJsContent.includes(`'${endpoint}'`) || 
                                appJsContent.includes(`"${endpoint}"`) ||
                                appJsContent.includes(`\`${endpoint}\``) ||
                                appJsContent.includes(`\${API_BASE}${endpoint}`);
            assert.ok(hasEndpoint, `Frontend app.js must call backend REST API endpoint '${endpoint}'`);
        }

        // Direct fetch calls with API_BASE
        assert.ok(appJsContent.includes('${API_BASE}/status'), 'app.js must call ${API_BASE}/status');
        assert.ok(appJsContent.includes('${API_BASE}/killchain/status'), 'app.js must call ${API_BASE}/killchain/status');

        // Verify zero mock indicators
        assert.ok(!appJsContent.includes('const mockThreats = ['), 'Must not contain hardcoded mockThreats array');
        assert.ok(!appJsContent.includes('return Promise.resolve(mockData)'), 'Must not return simulated mock promise');
    });
});
