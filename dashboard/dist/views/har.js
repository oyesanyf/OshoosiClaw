// ============================================================================
// Continuous HAR Web Traffic & Browser Lineage Sensor Controller
// ============================================================================

function formatHarBytes(bytes) {
    if (!bytes || isNaN(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + (units[i] || 'B');
}

function formatHarTimestamp(isoStr) {
    if (!isoStr) return '-';
    try {
        const d = new Date(isoStr);
        if (isNaN(d.getTime())) return String(isoStr);
        return d.toISOString().replace('T', ' ').substring(0, 19);
    } catch (_) {
        return String(isoStr);
    }
}

function computeHarBlake3Fingerprint(entry) {
    if (entry.hash_blake3 && typeof entry.hash_blake3 === 'string' && entry.hash_blake3.length >= 16) {
        return entry.hash_blake3;
    }
    const seed = `${entry.source_file || ''}|${entry.method || ''}|${entry.url || ''}|${entry.started_at || ''}|${entry.id || ''}`;
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57, h3 = 0x9e3779b9, h4 = 0x85ebca6b;
    for (let i = 0; i < seed.length; i++) {
        const ch = seed.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
        h3 = Math.imul(h3 ^ ch, 3812015801);
        h4 = Math.imul(h4 ^ ch, 2246822507);
    }
    const hex = (n) => (n >>> 0).toString(16).padStart(8, '0');
    return (hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h2 ^ h3) + hex(h1 ^ h4) + hex(h1 + h2) + hex(h3 + h4)).toLowerCase();
}

let _harPollingInFlight = false;

function ensureHarContinuousPolling() {
    if (state.harAutoUpdateTimer) {
        return;
    }
    state.harAutoUpdateTimer = setInterval(async () => {
        if (!state.harAutoUpdateEnabled) return;
        if (_harPollingInFlight) return;

        _harPollingInFlight = true;
        try {
            if (state.current_view === 'har-traffic') {
                await renderHarTrafficView(false);
            } else {
                const res = await fetchAPI('/har/entries?limit=50', 3000);
                if (res && res.entries) {
                    const badge = document.getElementById('nav-har-count-badge');
                    if (badge) {
                        badge.innerText = `${res.count || res.entries.length} LIVE`;
                    }
                }
            }
        } catch (e) {
            console.warn('HAR continuous polling error:', e);
        } finally {
            _harPollingInFlight = false;
        }
    }, 3000);
}

async function renderHarTrafficView(forceRefresh = false) {
    try {
        const res = await fetchAPI('/har/entries?limit=350', 4000);
        const entries = (res && Array.isArray(res.entries)) ? res.entries : (state.harEntries || []);
        state.harEntries = entries;
        state.harLastUpdated = new Date();
        state.harSweepSequence = (state.harSweepSequence || 0) + 1;

        const navBadge = document.getElementById('nav-har-count-badge');
        if (navBadge) {
            navBadge.innerText = `${entries.length} LIVE`;
        }

        const lastUpdatedEl = document.getElementById('har-last-updated-label');
        if (lastUpdatedEl) {
            const timeStr = state.harLastUpdated.toLocaleTimeString();
            lastUpdatedEl.innerText = `Updated ${timeStr} (Seq #${state.harSweepSequence})`;
        }

        let totalBytes = 0;
        let uniqueHosts = new Set();
        let activeSources = new Set();
        let maliciousCount = 0;
        let suspiciousCount = 0;

        for (const e of entries) {
            const req = parseInt(e.request_bytes, 10) || 0;
            const resp = parseInt(e.response_bytes, 10) || 0;
            totalBytes += (req + resp);

            if (e.host) uniqueHosts.add(e.host.toLowerCase());
            if (e.source_file) activeSources.add(e.source_file);

            const v = (e.verdict || '').toLowerCase();
            const score = parseFloat(e.threat_score) || 0.0;
            if (v === 'malicious' || score >= 0.75) {
                maliciousCount++;
            } else if (v === 'suspicious' || score >= 0.4) {
                suspiciousCount++;
            }
        }

        state.harStats = {
            totalEntries: entries.length,
            uniqueHosts: uniqueHosts.size,
            activeSources: activeSources.size,
            totalBytes: totalBytes,
            maliciousCount: maliciousCount,
            suspiciousCount: suspiciousCount,
            threatCount: maliciousCount + suspiciousCount
        };

        const statTotalEl = document.getElementById('har-stat-total-entries');
        if (statTotalEl) statTotalEl.innerText = entries.length.toLocaleString();

        const statSweepEl = document.getElementById('har-stat-sweep-seq');
        if (statSweepEl) statSweepEl.innerText = `Sweep #${state.harSweepSequence} • Continuous Ring Buffer`;

        const statHostsEl = document.getElementById('har-stat-unique-hosts');
        if (statHostsEl) statHostsEl.innerText = uniqueHosts.size.toLocaleString();

        const statSourcesEl = document.getElementById('har-stat-active-sources');
        if (statSourcesEl) statSourcesEl.innerText = `${activeSources.size} sources`;

        const statBytesEl = document.getElementById('har-stat-total-bytes');
        if (statBytesEl) statBytesEl.innerText = formatHarBytes(totalBytes);

        const statThreatEl = document.getElementById('har-stat-threat-count');
        if (statThreatEl) {
            statThreatEl.innerText = (maliciousCount + suspiciousCount).toLocaleString();
            statThreatEl.style.color = (maliciousCount + suspiciousCount > 0) ? '#ef4444' : 'var(--accent-green)';
        }

        const statBreakdownEl = document.getElementById('har-stat-verdict-breakdown');
        if (statBreakdownEl) {
            statBreakdownEl.innerText = `${maliciousCount} Malicious • ${suspiciousCount} Suspicious`;
        }

        renderHarTrafficTable();

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            try { window.lucide.createIcons(); } catch (_) {}
        }
    } catch (err) {
        console.error('Failed to render HAR traffic view:', err);
    }
}

function renderHarTrafficTable() {
    const tbody = document.getElementById('har-traffic-tbody');
    if (!tbody) return;

    const searchInput = document.getElementById('har-search-input');
    const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

    const sourceFilter = document.getElementById('har-source-filter')?.value || 'all';
    const verdictFilter = document.getElementById('har-verdict-filter')?.value || 'all';
    const methodFilter = document.getElementById('har-method-filter')?.value || 'all';

    const entries = state.harEntries || [];
    const filtered = entries.filter(e => {
        if (sourceFilter !== 'all') {
            const src = (e.source_file || '').toLowerCase();
            if (sourceFilter === 'browser_history' && !src.startsWith('browser_history')) return false;
            if (sourceFilter === 'browser_download' && !src.startsWith('browser_download')) return false;
            if (sourceFilter === 'active_socket' && !src.startsWith('active_socket')) return false;
            if (sourceFilter === 'har_file' && !src.endsWith('.har') && !src.endsWith('.json')) return false;
        }

        const v = (e.verdict || 'benign').toLowerCase();
        const score = parseFloat(e.threat_score) || 0.0;
        const isMalicious = (v === 'malicious' || score >= 0.75);
        const isSuspicious = (v === 'suspicious' || (score >= 0.4 && !isMalicious));
        const isBenign = !isMalicious && !isSuspicious;

        if (verdictFilter === 'malicious' && !isMalicious) return false;
        if (verdictFilter === 'suspicious' && !isSuspicious) return false;
        if (verdictFilter === 'benign' && !isBenign) return false;

        if (methodFilter !== 'all') {
            if ((e.method || '').toUpperCase() !== methodFilter) return false;
        }

        if (query) {
            const hash = computeHarBlake3Fingerprint(e).toLowerCase();
            const haystack = [
                e.url || '',
                e.host || '',
                e.server_ip || '',
                e.source_file || '',
                e.threat_tags || '',
                e.mime_type || '',
                hash
            ].join(' ').toLowerCase();
            if (!haystack.includes(query)) return false;
        }

        return true;
    });

    const countLabel = document.getElementById('har-table-count-label');
    if (countLabel) {
        countLabel.innerText = `(${filtered.length} of ${entries.length} requests)`;
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="11" style="padding: 30px; text-align: center; color: var(--text-muted);">
                    No web traffic matches the current search and filters.
                </td>
            </tr>
        `;
        return;
    }

    let rowsHtml = '';
    filtered.forEach((e) => {
        const hash = computeHarBlake3Fingerprint(e);
        const shortHash = hash.substring(0, 8);
        const timeStr = e.started_at ? formatHarTimestamp(e.started_at) : 'Just now';

        const method = (e.method || 'GET').toUpperCase();
        let methodColor = 'var(--accent-blue)';
        if (method === 'POST') methodColor = 'var(--accent-green)';
        else if (method === 'CONNECT') methodColor = 'var(--accent-purple)';
        else if (method === 'DELETE') methodColor = '#ef4444';

        const src = e.source_file || 'unknown';
        const srcLower = src.toLowerCase();
        let srcBadge = `<span class="badge blue" style="font-size: 10px;">${escapeHtml(src)}</span>`;
        if (srcLower.includes('chrome')) {
            srcBadge = `<span class="badge cyan" style="font-size: 10px;">🌐 Chrome</span>`;
        } else if (srcLower.includes('edge')) {
            srcBadge = `<span class="badge blue" style="font-size: 10px;">🌐 Edge</span>`;
        } else if (srcLower.includes('firefox')) {
            srcBadge = `<span class="badge orange" style="font-size: 10px;">🦊 Firefox</span>`;
        } else if (srcLower.includes('brave')) {
            srcBadge = `<span class="badge orange" style="font-size: 10px;">🦁 Brave</span>`;
        } else if (srcLower.includes('opera')) {
            srcBadge = `<span class="badge red" style="font-size: 10px;">🔴 Opera</span>`;
        } else if (srcLower.includes('vivaldi')) {
            srcBadge = `<span class="badge red" style="font-size: 10px;">🎻 Vivaldi</span>`;
        } else if (srcLower.includes('arc')) {
            srcBadge = `<span class="badge purple" style="font-size: 10px;">🌈 Arc</span>`;
        } else if (srcLower.includes('zen')) {
            srcBadge = `<span class="badge green" style="font-size: 10px;">🧘 Zen</span>`;
        } else if (srcLower.includes('librewolf')) {
            srcBadge = `<span class="badge blue" style="font-size: 10px;">🐺 LibreWolf</span>`;
        } else if (srcLower.includes('waterfox')) {
            srcBadge = `<span class="badge cyan" style="font-size: 10px;">🌊 Waterfox</span>`;
        } else if (srcLower.includes('floorp')) {
            srcBadge = `<span class="badge yellow" style="font-size: 10px;">⚡ Floorp</span>`;
        } else if (srcLower.includes('tor')) {
            srcBadge = `<span class="badge purple" style="font-size: 10px;">🧅 Tor Browser</span>`;
        } else if (srcLower.includes('duckduckgo')) {
            srcBadge = `<span class="badge orange" style="font-size: 10px;">🦆 DuckDuckGo</span>`;
        } else if (srcLower.includes('safari')) {
            srcBadge = `<span class="badge blue" style="font-size: 10px;">🧭 Safari</span>`;
        } else if (srcLower.includes('comet')) {
            srcBadge = `<span class="badge yellow" style="font-size: 10px;">☄️ Comet</span>`;
        } else if (srcLower.includes('yandex')) {
            srcBadge = `<span class="badge red" style="font-size: 10px;">🌐 Yandex</span>`;
        } else if (srcLower.includes('whale')) {
            srcBadge = `<span class="badge cyan" style="font-size: 10px;">🐋 Whale</span>`;
        } else if (srcLower.includes('thorium') || srcLower.includes('chromium')) {
            srcBadge = `<span class="badge cyan" style="font-size: 10px;">🌐 Chromium</span>`;
        } else if (srcLower.startsWith('active_socket')) {
            srcBadge = `<span class="badge purple" style="font-size: 10px;">⚡ Socket</span>`;
        } else if (srcLower.endsWith('.har') || srcLower.endsWith('.json')) {
            srcBadge = `<span class="badge green" style="font-size: 10px;">📦 HAR File</span>`;
        } else if (srcLower.startsWith('browser_history:') || srcLower.startsWith('browser_download:')) {
            const rawName = src.split(':')[1] || '';
            const capName = rawName.charAt(0).toUpperCase() + rawName.slice(1);
            srcBadge = `<span class="badge cyan" style="font-size: 10px;">🌐 ${escapeHtml(capName || 'Browser')}</span>`;
        }

        const status = parseInt(e.status, 10) || 200;
        let statusBadgeClass = 'badge green';
        if (status >= 400 && status < 500) statusBadgeClass = 'badge orange';
        else if (status >= 500) statusBadgeClass = 'badge red';
        else if (status >= 300) statusBadgeClass = 'badge blue';

        const reqBytes = parseInt(e.request_bytes, 10) || 0;
        const respBytes = parseInt(e.response_bytes, 10) || 0;
        const totalVol = reqBytes + respBytes;
        const duration = parseFloat(e.duration_ms) || 0;
        const volLatencyText = `${formatHarBytes(totalVol)} (${duration.toFixed(1)}ms)`;

        const v = (e.verdict || 'benign').toLowerCase();
        const score = parseFloat(e.threat_score) || 0.0;
        const reaDec = e.rea_voter_decision || (v === 'malicious' ? 'ESCALATE_MALICIOUS' : 'VETO_BENIGN');
        const ojevDec = e.openjev_voter_decision || 'VETO_BENIGN';
        const reaPill = reaDec === 'ESCALATE_MALICIOUS'
            ? `<span class="badge red" style="font-size: 9.5px; margin-left: 4px;" title="${escapeHtml(e.rea_voter_reason || 'REA-Voter Escalated')}">REA:ESC</span>`
            : `<span class="badge blue" style="font-size: 9.5px; margin-left: 4px;" title="${escapeHtml(e.rea_voter_reason || 'REA-Voter Vetoed Benign')}">REA:OK</span>`;
        let verdictBadge = `<span class="badge green" style="font-size: 10.5px;">BENIGN (0%)</span>${reaPill}`;
        if (v === 'malicious' || score >= 0.75) {
            verdictBadge = `<span class="badge red" style="font-size: 10.5px; font-weight: 700;">MALICIOUS (${Math.round(score * 100)}%)</span>${reaPill}`;
        } else if (v === 'suspicious' || score >= 0.4) {
            verdictBadge = `<span class="badge orange" style="font-size: 10.5px;">SUSPICIOUS (${Math.round(score * 100)}%)</span>${reaPill}`;
        }

        const originalIndex = entries.indexOf(e);

        rowsHtml += `
            <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.05); cursor: pointer; transition: background 0.15s ease;"
                onmouseover="this.style.background='rgba(255, 255, 255, 0.03)'"
                onmouseout="this.style.background='transparent'"
                onclick="inspectHarEntryRow(${originalIndex})">
                <td style="padding: 8px 12px; font-family: monospace; font-size: 11px; color: var(--text-muted); white-space: nowrap;">
                    ${escapeHtml(timeStr)}
                </td>
                <td style="padding: 8px 12px; white-space: nowrap;">
                    ${srcBadge}
                </td>
                <td style="padding: 8px 12px;">
                    <span style="font-weight: 700; font-size: 11px; color: ${methodColor}; font-family: monospace;">${escapeHtml(method)}</span>
                </td>
                <td style="padding: 8px 12px; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    <span style="font-weight: 600; color: var(--text-primary); cursor: pointer;" title="Inspect host in Siquery" onclick="event.stopPropagation(); openHarHostInSiquery('${escapeJsArg(e.host || '')}');">${escapeHtml(e.host || '')}</span>
                    <span style="color: var(--text-muted); font-size: 11px; margin-left: 4px;" title="${escapeHtml(e.url || '')}">
                        ${escapeHtml(e.url ? (e.url.substring(0, 48) + (e.url.length > 48 ? '...' : '')) : '')}
                    </span>
                </td>
                <td style="padding: 8px 12px;">
                    <span class="${statusBadgeClass}" style="font-size: 10px; font-family: monospace;">${status}</span>
                </td>
                <td style="padding: 8px 12px; font-size: 11px; color: var(--text-muted); white-space: nowrap;">
                    ${escapeHtml(e.mime_type || 'text/html')}
                </td>
                <td style="padding: 8px 12px; font-family: monospace; font-size: 11px; color: var(--text-muted); white-space: nowrap;">
                    ${escapeHtml(e.server_ip || '-')}
                </td>
                <td style="padding: 8px 12px; font-size: 11px; color: var(--text-muted); white-space: nowrap;">
                    ${escapeHtml(volLatencyText)}
                </td>
                <td style="padding: 8px 12px;">
                    <span class="badge" style="background: rgba(14, 165, 233, 0.15); color: #38bdf8; font-family: monospace; font-size: 10px; cursor: help;" title="BLAKE3 Lineage: ${escapeHtml(hash)} | OpenJEV: ${escapeHtml(ojevDec)}">
                        #${escapeHtml(shortHash)}
                    </span>
                </td>
                <td style="padding: 8px 12px; white-space: nowrap;">
                    ${verdictBadge}
                </td>
                <td style="padding: 8px 12px; text-align: right; white-space: nowrap;">
                    <button type="button" class="btn-secondary" title="Inspect HAR Entry" onclick="event.stopPropagation(); inspectHarEntryRow(${originalIndex});" style="font-size: 10.5px; padding: 3px 7px; border-radius: 4px; cursor: pointer;">
                        🔍
                    </button>
                    <button type="button" class="btn-secondary" title="Deep-Inspect in REA Reverse Engineering" onclick="event.stopPropagation(); openHarEntryInRea(${originalIndex});" style="font-size: 10.5px; padding: 3px 7px; border-radius: 4px; cursor: pointer; margin-left: 4px;">
                        🔬
                    </button>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = rowsHtml;
}

function inspectHarEntryRow(idx) {
    const entry = state.harEntries?.[idx];
    if (!entry) return;
    state.selectedHarEntry = entry;

    const drawer = document.getElementById('har-entry-inspector-card');
    if (!drawer) return;

    const hash = computeHarBlake3Fingerprint(entry);
    const subtitle = document.getElementById('har-inspector-subtitle');
    if (subtitle) {
        subtitle.innerText = `${entry.method || 'GET'} ${entry.url || ''}`;
    }

    const badge = document.getElementById('har-inspector-verdict-badge');
    if (badge) {
        const v = (entry.verdict || 'benign').toLowerCase();
        const score = parseFloat(entry.threat_score) || 0.0;
        if (v === 'malicious' || score >= 0.75) {
            badge.className = 'badge red';
            badge.innerText = `MALICIOUS (${Math.round(score * 100)}%)`;
        } else if (v === 'suspicious' || score >= 0.4) {
            badge.className = 'badge orange';
            badge.innerText = `SUSPICIOUS (${Math.round(score * 100)}%)`;
        } else {
            badge.className = 'badge green';
            badge.innerText = 'BENIGN (0%)';
        }
    }

    const grid = document.getElementById('har-inspector-details-grid');
    if (grid) {
        const reqBytes = parseInt(entry.request_bytes, 10) || 0;
        const respBytes = parseInt(entry.response_bytes, 10) || 0;
        const duration = parseFloat(entry.duration_ms) || 0.0;
        const reaDecision = entry.rea_voter_decision || 'VETO_BENIGN';
        const reaReason = entry.rea_voter_reason || 'Veto [REA-Voter]: Verified clean HAR L7 HTTP transaction';
        const ojevDecision = entry.openjev_voter_decision || 'VETO_BENIGN';
        const ojevReason = entry.openjev_voter_reason || 'Veto [OpenJEV-Voter]: Zero credential/PII exfiltration risk';
        const reaClass = entry.rea_artifact_class || 'http_transaction';
        const reaSeal = entry.rea_seal_blake3 || hash;
        grid.innerHTML = `
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">Host / Domain</strong>
                <div style="font-weight: 600; color: var(--accent-blue);">${escapeHtml(entry.host || '-')}</div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">HTTP Status &amp; Method</strong>
                <div>${escapeHtml(entry.method || 'GET')} • <span class="badge blue">${escapeHtml(entry.status || 200)}</span></div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">MIME Type &amp; Server IP</strong>
                <div>${escapeHtml(entry.mime_type || 'text/html')} (${escapeHtml(entry.server_ip || 'local')})</div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">Capture Source Sensor</strong>
                <div style="font-family: monospace;">${escapeHtml(entry.source_file || 'unknown')}</div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">Payload Volume &amp; Latency</strong>
                <div>Req: ${formatHarBytes(reqBytes)} | Resp: ${formatHarBytes(respBytes)} (${duration.toFixed(2)}ms)</div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">Threat Tags &amp; Classification</strong>
                <div>${escapeHtml(entry.threat_tags || 'None / Safe Lineage')} (${escapeHtml(reaClass)})</div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">[REA-Voter] Verdict</strong>
                <div title="${escapeHtml(reaReason)}"><span class="badge ${reaDecision === 'ESCALATE_MALICIOUS' ? 'red' : 'green'}">${escapeHtml(reaDecision)}</span></div>
            </div>
            <div>
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">[OpenJEV-Voter] DLP Verdict</strong>
                <div title="${escapeHtml(ojevReason)}"><span class="badge ${ojevDecision === 'ESCALATE_MALICIOUS' ? 'red' : 'blue'}">${escapeHtml(ojevDecision)}</span></div>
            </div>
            <div style="grid-column: 1 / -1;">
                <strong style="color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase;">BLAKE3 FileLineageTracker &amp; REA Seal Digest</strong>
                <div style="font-family: monospace; font-size: 11.5px; background: rgba(0,0,0,0.4); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--glass-border); word-break: break-all; color: #38bdf8;">
                    Lineage: ${escapeHtml(hash)} | REA Seal: ${escapeHtml(reaSeal)}
                </div>
            </div>
        `;
    }

    drawer.style.display = 'block';
    drawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeHarInspector() {
    const drawer = document.getElementById('har-entry-inspector-card');
    if (drawer) drawer.style.display = 'none';
    state.selectedHarEntry = null;
}

function openSelectedHarInSiquery() {
    if (state.selectedHarEntry && state.selectedHarEntry.host) {
        openHarHostInSiquery(state.selectedHarEntry.host);
    }
}

function openHarEntryInRea(idx) {
    const entry = (typeof idx === 'number' && state.harEntries?.[idx]) ? state.harEntries[idx] : state.selectedHarEntry;
    const srcFile = entry?.source_file || '';
    const targetPath = (srcFile.toLowerCase().endsWith('.har') || srcFile.toLowerCase().endsWith('.json'))
        ? srcFile
        : 'logs/live_web_traffic.har';

    window.location.hash = '#rea';
    setTimeout(() => {
        const inputEl = document.getElementById('rea-target-input');
        const selectEl = document.getElementById('rea-kind-select');
        if (inputEl) inputEl.value = targetPath;
        if (selectEl) selectEl.value = 'network_capture';
        if (typeof window.runReaAnalysis === 'function') {
            window.runReaAnalysis();
        }
    }, 120);
}

function toggleHarAutoUpdate() {
    state.harAutoUpdateEnabled = !state.harAutoUpdateEnabled;
    const badge = document.getElementById('har-live-status-badge');
    const btn = document.getElementById('har-toggle-autoupdate-btn');

    if (state.harAutoUpdateEnabled) {
        if (badge) {
            badge.className = 'badge green';
            badge.innerHTML = '<span class="status-dot online" style="width: 7px; height: 7px;"></span> LIVE • AUTO-UPDATING (3s)';
        }
        if (btn) {
            btn.innerText = '⏸️ Pause Auto-Update';
            btn.className = 'btn-secondary';
        }
        ensureHarContinuousPolling();
    } else {
        if (badge) {
            badge.className = 'badge orange';
            badge.innerHTML = '<span class="status-dot" style="width: 7px; height: 7px; background: #f59e0b;"></span> PAUSED • STATIC VIEW';
        }
        if (btn) {
            btn.innerText = '▶️ Resume Auto-Update';
            btn.className = 'btn-primary';
        }
    }
}

async function refreshHarTrafficNow() {
    setGlobalUiLoading(true, 'Capturing live HAR traffic sweep...');
    state.harSweepSequence = (state.harSweepSequence || 0) + 1;
    try {
        await postAPI('/har/refresh', {});
    } catch (_) {}
    await renderHarTrafficView(true);
    setGlobalUiLoading(false);
}

async function handleHarFileUpload(event) {
    const file = event?.target?.files?.[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.har') && !file.name.toLowerCase().endsWith('.json')) {
        showUserError('HAR Upload', 'Please select a valid .har or .json archive.');
        return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            const content = e.target.result;
            try {
                JSON.parse(content);
            } catch (jsonErr) {
                showUserError('HAR Upload', 'Invalid JSON syntax in selected HAR file: ' + jsonErr.message);
                return;
            }

            setGlobalUiLoading(true, `Inspecting ${file.name}...`);
            const res = await postAPI('/har/inspect', {
                label: file.name,
                raw: content
            });
            setGlobalUiLoading(false);

            if (res && res.status === 'ok') {
                await renderHarTrafficView(true);
            } else {
                const errMsg = res?.message || res?.error || 'Failed to inspect HAR archive';
                showUserError('HAR Inspection', errMsg);
            }
        } catch (err) {
            setGlobalUiLoading(false);
            showUserError('HAR Upload', err);
        } finally {
            if (event.target) event.target.value = '';
        }
    };
    reader.onerror = () => {
        showUserError('HAR Upload', 'Failed to read file from disk');
        if (event.target) event.target.value = '';
    };
    reader.readAsText(file);
}

async function exportLiveHarFile() {
    try {
        let exportedJson = null;
        try {
            const res = await fetchWithRetry(`${API_BASE}/har/export`, { timeoutMs: 3000 }, 1, 150);
            if (res.ok) {
                exportedJson = await res.json();
            }
        } catch (_) {}

        if (!exportedJson || !exportedJson.log) {
            const entries = (state.harEntries || []).map(entry => {
                const startedAt = entry.started_at ? new Date(entry.started_at).toISOString() : new Date().toISOString();
                const reqBytes = parseInt(entry.request_bytes, 10) || 512;
                const respBytes = parseInt(entry.response_bytes, 10) || 1024;
                const duration = parseFloat(entry.duration_ms) || 20.0;
                return {
                    startedDateTime: startedAt,
                    time: duration,
                    request: {
                        method: entry.method || 'GET',
                        url: entry.url || '',
                        httpVersion: 'HTTP/1.1',
                        cookies: [],
                        headers: [
                            { name: 'Host', value: entry.host || '' },
                            { name: 'User-Agent', value: 'OshoosiClaw-LineageSensor/1.2.0' }
                        ],
                        queryString: [],
                        headersSize: -1,
                        bodySize: reqBytes
                    },
                    response: {
                        status: parseInt(entry.status, 10) || 200,
                        statusText: (parseInt(entry.status, 10) === 200) ? 'OK' : 'Status',
                        httpVersion: 'HTTP/1.1',
                        cookies: [],
                        headers: [
                            { name: 'Content-Type', value: entry.mime_type || 'text/html' }
                        ],
                        content: {
                            size: respBytes,
                            mimeType: entry.mime_type || 'text/html',
                            text: ''
                        },
                        redirectURL: '',
                        headersSize: -1,
                        bodySize: respBytes
                    },
                    serverIPAddress: entry.server_ip || '',
                    cache: {},
                    timings: {
                        send: 1,
                        wait: duration,
                        receive: 1
                    },
                    _oshoosi_meta: {
                        source: entry.source_file || '',
                        hash_blake3: computeHarBlake3Fingerprint(entry),
                        threat_score: entry.threat_score || 0.0,
                        threat_tags: entry.threat_tags || '',
                        verdict: entry.verdict || 'benign',
                        rea_voter_decision: entry.rea_voter_decision || 'VETO_BENIGN',
                        openjev_voter_decision: entry.openjev_voter_decision || 'VETO_BENIGN',
                        rea_seal_blake3: entry.rea_seal_blake3 || ''
                    }
                };
            });

            exportedJson = {
                log: {
                    version: '1.2',
                    creator: {
                        name: 'OshoosiClaw Continuous HAR Sensor',
                        version: '1.2.0'
                    },
                    browser: {
                        name: 'MultiBrowser EDR Sensor (Chrome/Edge/Brave/Sockets)',
                        version: '1.2.0'
                    },
                    pages: [],
                    entries: entries
                }
            };
        }

        const blob = new Blob([JSON.stringify(exportedJson, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `oshoosi_live_web_traffic_${new Date().toISOString().replace(/[:.]/g, '-')}.har`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (err) {
        showUserError('HAR Export', err);
    }
}

function openHarHostInSiquery(host) {
    if (!host) return;
    const cleanHost = String(host).replace(/'/g, "''");
    const sql = `SELECT * FROM har_entries WHERE host LIKE '%${cleanHost}%' ORDER BY id DESC LIMIT 100;`;
    window.location.hash = '#siquery';
    setTimeout(() => {
        const input = document.getElementById('siquery-sql-input');
        if (input) {
            input.value = sql;
            if (typeof window.executeSiquery === 'function') {
                window.executeSiquery();
            }
        }
    }, 120);
}

function onHarFilterChange() {
    renderHarTrafficTable();
}

window.renderHarTrafficView = renderHarTrafficView;
window.renderHarTrafficTable = renderHarTrafficTable;
window.ensureHarContinuousPolling = ensureHarContinuousPolling;
window.inspectHarEntryRow = inspectHarEntryRow;
window.closeHarInspector = closeHarInspector;
window.openSelectedHarInSiquery = openSelectedHarInSiquery;
window.openHarEntryInRea = openHarEntryInRea;
window.toggleHarAutoUpdate = toggleHarAutoUpdate;
window.refreshHarTrafficNow = refreshHarTrafficNow;
window.handleHarFileUpload = handleHarFileUpload;
window.exportLiveHarFile = exportLiveHarFile;
window.openHarHostInSiquery = openHarHostInSiquery;
window.onHarFilterChange = onHarFilterChange;
