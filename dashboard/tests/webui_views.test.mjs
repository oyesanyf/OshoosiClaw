import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

describe('WebUI 19 Views & 5 Operational Modals Verification (Feature 14)', () => {
    const htmlPath = path.resolve('dashboard/src/index.html');
    const htmlContent = fs.readFileSync(htmlPath, 'utf-8');

    const expectedViews = [
        'dashboard',
        'zone',
        'approvals',
        'otel-map',
        'threats',
        'mitre',
        'mesh',
        'gossip',
        'malware',
        'killchain',
        'repair',
        'utilities',
        'process-map',
        'story',
        'history',
        'skyrl',
        'agent-anomalies',
        'siquery',
        'rea',
        'har-traffic',
        'adversarial-tests',
        'dlp',
        'cicd-protection'
    ];

    const expectedModals = [
        'login-overlay',
        'killchain-action-modal',
        'password-reset-modal',
        'mitre-technique-modal',
        'supervisor-modal'
    ];

    it('should assert that all 23 navigation views exist with data-view attributes', () => {
        const dataViewMatches = [...htmlContent.matchAll(/data-view=["']([^"']+)["']/g)].map(m => m[1]);
        assert.strictEqual(dataViewMatches.length, 23, 'Must contain all 23 data-view navigation items');

        for (const view of expectedViews) {
            assert.ok(dataViewMatches.includes(view), `View '${view}' must be defined in sidebar navigation`);
        }
    });

    it('should assert that corresponding view content sections exist for all 23 views', () => {
        for (const view of expectedViews) {
            // View sections use id="<view>-view" or id="view-<view>" or id="<view>"
            const patterns = [
                new RegExp(`id=["']${view}-view["']`, 'i'),
                new RegExp(`id=["']view-${view}["']`, 'i'),
                new RegExp(`id=["']${view}["']`, 'i'),
                new RegExp(`class=["'][^"']*view-content[^"']*["'][^>]*id=["'][^"']*${view}[^"']*["']`, 'i')
            ];
            const found = patterns.some(p => p.test(htmlContent));
            assert.ok(found, `Content container for view '${view}' must exist in index.html`);
        }
    });

    it('should assert that all 5 operational modals exist in the DOM structure', () => {
        for (const modalId of expectedModals) {
            const hasModal = htmlContent.includes(`id="${modalId}"`);
            assert.ok(hasModal, `Operational modal container '${modalId}' must exist in index.html`);
        }
    });

    it('should assert that modal close buttons or escape listeners are defined', () => {
        assert.ok(htmlContent.includes('close-mitre-modal-btn'), 'MITRE modal must have close button');
        assert.ok(htmlContent.includes('close-supervisor-modal-btn'), 'Supervisor modal must have close button');
        assert.ok(htmlContent.includes('closeKillchainModal()'), 'Killchain modal must have closeKillchainModal() handler');
    });
});
