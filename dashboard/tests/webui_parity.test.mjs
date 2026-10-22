import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

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
