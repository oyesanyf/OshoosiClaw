import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const srcDir = path.resolve(__dirname, '../src');

describe('Universal WebUI Loading Spinners & Status Messages Verification', () => {
    const html = fs.readFileSync(path.join(srcDir, 'index.html'), 'utf-8');
    const js = fs.readFileSync(path.join(srcDir, 'app.js'), 'utf-8');
    const css = fs.readFileSync(path.join(srcDir, 'style.css'), 'utf-8');

    it('should include login status banner and inline button spinners in index.html', () => {
        assert.ok(html.includes('id="login-status-banner"'), 'Missing #login-status-banner on Login page');
        assert.ok(html.includes('id="login-status-text"'), 'Missing #login-status-text on Login page');
        assert.ok(html.includes('id="login-btn-spinner"'), 'Missing #login-btn-spinner on Access System button');
        assert.ok(html.includes('id="hello-btn-spinner"'), 'Missing #hello-btn-spinner on Windows Hello button');
    });

    it('should include global header loading pill and progress shimmer bar in index.html', () => {
        assert.ok(html.includes('id="global-ui-loading-pill"'), 'Missing #global-ui-loading-pill in top header');
        assert.ok(html.includes('id="global-ui-loading-text"'), 'Missing #global-ui-loading-text in top header');
        assert.ok(html.includes('id="global-ui-progress-bar"'), 'Missing #global-ui-progress-bar at top of viewport');
    });

    it('should define spinner animations and status banner styles in style.css', () => {
        assert.ok(css.includes('@keyframes oshoosi-spin'), 'Missing @keyframes oshoosi-spin in style.css');
        assert.ok(css.includes('.oshoosi-spinner'), 'Missing .oshoosi-spinner class in style.css');
        assert.ok(css.includes('.login-status-banner'), 'Missing .login-status-banner class in style.css');
        assert.ok(css.includes('.global-ui-loading-pill'), 'Missing .global-ui-loading-pill class in style.css');
        assert.ok(css.includes('.global-ui-progress-bar'), 'Missing .global-ui-progress-bar class in style.css');
    });

    it('should wire login, button, fetch, and view navigation loading indicators in app.js', () => {
        assert.ok(js.includes('function setLoginLoadingState('), 'Missing setLoginLoadingState helper in app.js');
        assert.ok(js.includes('function setGlobalUiLoading('), 'Missing setGlobalUiLoading helper in app.js');
        assert.ok(js.includes('function setButtonLoadingState('), 'Missing setButtonLoadingState helper in app.js');
        assert.ok(js.includes('function showViewLoadingFeedback('), 'Missing showViewLoadingFeedback helper in app.js');
        assert.ok(js.includes('function setupUniversalUiLoadingInterceptors('), 'Missing setupUniversalUiLoadingInterceptors in app.js');
    });
});
