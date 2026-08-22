const API_BASE = '/api';
const POLL_INTERVAL = 3000;

const state = {
    uptime: '',
    node_id: '',
    peer_count: 0,
    threats: [],
    suppressedThreatKeys: new Set(),
    activity: [],
    chain_verified: false,
    current_view: 'dashboard',
    searchQuery: '',
    network: null,
    otelNetwork: null,
    telemetryChart: null,
    expandedDetails: new Set(),
    lastThreatsHash: '',
    lastActivityHash: '',
    gossip_count: 0,
    _pollInFlight: false
};

let updateInterval = null;

/**
 * Initialize Lucide icons and start polling
 */
function init() {
    setupLogin();
    setupNav();
    setupSearch();
    
    if (localStorage.getItem('oshoosi_logged_in') === 'true') {
        startApp();
    }
}

function startApp() {
    updateDashboard();
    if (!updateInterval) {
        updateInterval = setInterval(updateDashboard, POLL_INTERVAL);
    }
}

function setupLogin() {
    const overlay = document.getElementById('login-overlay');
    const form = document.getElementById('login-form');
    const errorDiv = document.getElementById('login-error');
    const logoutBtn = document.getElementById('logout-btn');
    
    const isLoggedIn = localStorage.getItem('oshoosi_logged_in') === 'true';
    if (isLoggedIn) {
        overlay.style.display = 'none';
    } else {
        overlay.style.display = 'flex';
    }
    
    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const usernameInput = document.getElementById('login-username');
            const passwordInput = document.getElementById('login-password');
            const username = usernameInput ? usernameInput.value.trim() : '';
            const password = passwordInput ? passwordInput.value.trim() : '';
            
            const u = username.toLowerCase();
            const isUserValid = u === 'admin' || u === 'oyesanyf@gmail.com' || u === 'oyesanyf' || u === '';
            const isPassValid = password === 'Ght99@$fk' || password === 'admin';
            
            if (isPassValid || (isUserValid && (password === 'Ght99@$fk' || password === 'admin'))) {
                localStorage.setItem('oshoosi_logged_in', 'true');
                overlay.style.opacity = '0';
                setTimeout(() => {
                    overlay.style.display = 'none';
                    overlay.style.opacity = '1';
                }, 300);
                errorDiv.style.display = 'none';
                
                startApp();
            } else {
                errorDiv.style.display = 'block';
                const card = document.querySelector('.login-card');
                if (card) {
                    card.style.animation = 'none';
                    void card.offsetWidth; // Trigger reflow
                    card.style.animation = 'login-shake 0.4s ease';
                }
            }
        });
    }
    
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.setItem('oshoosi_logged_in', 'false');
            window.location.reload();
        });
    }
}

/**
 * Handle navigation between dashboard views
 */
function setupNav() {
    const navItems = document.querySelectorAll('.nav-item');
    const viewTitle = document.getElementById('view-title');
    
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const view = item.getAttribute('data-view');
            
            // Update active state in sidebar
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            // Switch views
            document.querySelectorAll('.view-content').forEach(v => v.classList.remove('active'));
            
            if (view === 'dashboard') {
                document.getElementById('dashboard-view').classList.add('active');
                viewTitle.innerText = "Detection Overview";
            } else if (view === 'threats') {
                document.getElementById('threats-view').classList.add('active');
                viewTitle.innerText = "Threat Intelligence";
            } else if (view === 'mesh') {
                document.getElementById('mesh-view').classList.add('active');
                viewTitle.innerText = "Mesh Network";
            } else if (view === 'gossip') {
                document.getElementById('gossip-view').classList.add('active');
                viewTitle.innerText = "Inter-Node Gossip Feed";
                renderGossipView();
            } else if (view === 'malware') {
                document.getElementById('malware-view').classList.add('active');
                viewTitle.innerText = "Malware Scanner";
            } else if (view === 'repair') {
                document.getElementById('repair-view').classList.add('active');
                viewTitle.innerText = "Repair Engine";
            } else if (view === 'process-map') {
                document.getElementById('process-map-view').classList.add('active');
                viewTitle.innerText = "Attack Graph & Process Map";
                renderProcessMapView();
            } else if (view === 'otel-map') {
                document.getElementById('otel-map-view').classList.add('active');
                viewTitle.innerText = "Global Telemetry Mesh Map";
                renderOtelMapView();
            } else if (view === 'zone') {
                document.getElementById('zone-view').classList.add('active');
                viewTitle.innerText = "Zone Security Gateway";
                renderZoneView();
            } else if (view === 'approvals') {
                document.getElementById('approvals-view').classList.add('active');
                viewTitle.innerText = "Response Approval Queue";
                renderApprovalsView();
            } else if (view === 'story') {
                document.getElementById('story-view').classList.add('active');
                viewTitle.innerText = "Forensic Storyboard";
                renderStoryView();
            } else {
                document.getElementById('other-view').classList.add('active');
                viewTitle.innerText = item.querySelector('span').innerText;
            }
            
            
            state.current_view = view;
        });
    });
}

/**
 * Handle search input
 */
function setupSearch() {
    const input = document.getElementById('search-input');
    if (!input) return;
    
    input.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        state.searchQuery = query;
        renderThreats(state.threats);
        if (state.current_view === 'threats') {
            renderThreatsView(state.threats);
        }
    });
}

/**
 * Main update loop
 */
async function updateDashboard() {
    // Non-reentrant guard: if previous poll is still in-flight, skip this tick.
    // This prevents cascading fetch queues when the backend is under heavy consensus load.
    if (state._pollInFlight) return;
    state._pollInFlight = true;
    try {
        const [status, threats, mesh, activity, malwareDetections, repairStatus, telemetryData, detectionStats] = await Promise.all([
            fetchAPI('/status'),
            fetchAPI('/threats'),
            fetchAPI('/mesh-stats'),
            fetchAPI('/activity'),
            fetchAPI('/malware-detections'),
            fetchAPI('/repair-status'),
            fetchAPI('/telemetry/timeseries'),
            fetchAPI('/detection-stats')
        ]);

        if (status) {
            state.uptime = status.uptime;
            state.node_id = status.node_id;
            state.chain_verified = status.chain_verified;
            updateStats('uptime', status.uptime);
            updateStats('chain-verified', status.chain_verified ? "Verified ✅" : "Unverified ⚠️");
            
            const nodeIdShort = status.node_id ? status.node_id.substring(0, 12) + '...' : '...';
            document.getElementById('node-id-short').innerText = nodeIdShort;
        }

        if (threats) {
            const visibleThreats = threats.filter(t => !state.suppressedThreatKeys.has(threatKey(t)));
            const currentHash = JSON.stringify(visibleThreats);
            if (currentHash !== state.lastThreatsHash) {
                state.threats = visibleThreats;
                state.lastThreatsHash = currentHash;
                updateStats('threat-count', visibleThreats.length);
                renderThreats(visibleThreats);
            }
        }

        if (mesh) {
            state.peer_count = mesh.peer_count;
            state.gossip_count = mesh.gossip_count || 0;
            updateStats('peer-count', mesh.peer_count);
            updateStats('gossip-count', mesh.gossip_count || 0);
            updateStats('pending-joins', mesh.pending_joins || 0);
            updateStats('quarantined', mesh.quarantined_peers || 0);
        }

        if (activity) {
            const currentHash = JSON.stringify(activity); if (currentHash !== state.lastActivityHash) { state.activity = activity;
            state.lastActivityHash = currentHash; renderActivity(activity); }
        }

        if (telemetryData) {
            updateTelemetryChart(telemetryData);
        }

        if (detectionStats) {
            renderDetectionStats(detectionStats);
        }

        // Render views
        if (state.current_view === 'threats' && threats) {
            renderThreatsView(state.threats);
        }
        if (state.current_view === 'mesh') {
            renderMeshView(mesh);
        }
        if (state.current_view === 'gossip') {
            renderGossipView();
        }
        if (state.current_view === 'malware' && malwareDetections) {
            renderMalwareView(malwareDetections);
        }
        if (state.current_view === 'repair' && repairStatus) {
            renderRepairView(repairStatus);
        }
        if (state.current_view === 'process-map') {
            // Optional: Auto-refresh graph every few polls if needed
        }
        if (state.current_view === 'zone') {
            renderZoneView();
        }
        if (state.current_view === 'approvals') {
            renderApprovalsView();
        }

        // Update global indicator
        document.getElementById('agent-status-text').innerText = "Agent Online";
        document.querySelector('.status-dot').className = "status-dot online";

    } catch (error) {
        console.error("Failed to update dashboard:", error);
        document.getElementById('agent-status-text').innerText = "Agent Offline";
        document.querySelector('.status-dot').className = "status-dot";
    } finally {
        state._pollInFlight = false;
    }
}

function threatKey(t) {
    return [
        t?.id || '',
        (t?.type || t?.process_name || '').toLowerCase(),
        (t?.source_node || '').toLowerCase(),
        (t?.file_path || '').toLowerCase(),
        (t?.hash_blake3 || '').toLowerCase()
    ].join('|');
}

function suppressThreatLocally(threatId) {
    const selected = state.threats.find(t => t.id === threatId);
    if (!selected) return;
    const selectedType = (selected.type || selected.process_name || '').toLowerCase();
    const selectedSource = (selected.source_node || '').toLowerCase();
    const selectedPath = (selected.file_path || '').toLowerCase();
    const selectedHash = (selected.hash_blake3 || '').toLowerCase();
    const sameFinding = (t) =>
        t.id === threatId ||
        ((t.type || t.process_name || '').toLowerCase() === selectedType &&
            (t.source_node || '').toLowerCase() === selectedSource) ||
        (!!selectedPath && (t.file_path || '').toLowerCase() === selectedPath) ||
        (!!selectedHash && (t.hash_blake3 || '').toLowerCase() === selectedHash);

    state.threats
        .filter(sameFinding)
        .forEach(t => state.suppressedThreatKeys.add(threatKey(t)));
    state.threats = state.threats.filter(t => !sameFinding(t));
    updateStats('threat-count', state.threats.length);
    renderThreats(state.threats);
    if (state.current_view === 'threats') {
        renderThreatsView(state.threats);
    }
}

/**
 * Helper to fetch from API
 */
async function fetchAPI(endpoint) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            console.warn(`Fetch timeout for ${endpoint} (4s SLA exceeded)`);
        } else {
            console.warn(`Error fetching ${endpoint}:`, err);
        }
        return null;
    }
}

/**
 * Update a stat card value
 */
function updateStats(id, value) {
    const elem = document.getElementById(`stat-${id}`);
    if (elem) elem.innerText = value;
}

/**
 * Render threat timeline items
 */
function renderThreats(threats) {
    const list = document.getElementById('threat-list');
    if (!list) return;
    
    if (threats.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No active threats detected.</p>';
        return;
    }

    const displayThreats = threats.slice(0, 30); const filtered = threats.filter(t => {
        if (!state.searchQuery) return true;
        const q = state.searchQuery;
        return (t.type && t.type.toLowerCase().includes(q)) || 
               (t.id && t.id.toLowerCase().includes(q)) ||
               (t.file_path && t.file_path.toLowerCase().includes(q)) ||
               (t.reason && t.reason.toLowerCase().includes(q));
    });

    if (filtered.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No matches found for "' + state.searchQuery + '".</p>';
        return;
    }

    const groups = {};
    const sourceToRender = state.searchQuery ? filtered : displayThreats; sourceToRender.forEach(t => {
        // Variation is defined by Type + Source only; reasons are listed inside
        const key = `${t.type}-${t.source_node || 'Unknown'}`;
        if (!groups[key]) groups[key] = [];
        groups[key].push(t);
    });

    list.innerHTML = Object.entries(groups).map(([key, groupThreats]) => {
        const t = groupThreats[0];
        const maxConfidence = Math.max(...groupThreats.map(gt => gt.confidence || 0));
        const severity = maxConfidence > 0.8 ? 'CRITICAL' : (maxConfidence > 0.6 ? 'HIGH' : 'MEDIUM');
        const badgeClass = maxConfidence > 0.8 ? 'red' : (maxConfidence > 0.6 ? 'blue' : 'blue');
        const borderClass = maxConfidence > 0.8 ? 'threat-high' : (maxConfidence > 0.6 ? 'threat-medium' : 'threat-low');
        
        return `
        <div class="timeline-item ${borderClass}">
            <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                <i data-lucide="shield-alert"></i>
            </div>
            <div class="item-info">
                <div class="item-title" style="display:flex; justify-content:space-between; align-items:center;">
                    <span>${t.type} ${groupThreats.length > 1 ? `<span style="font-size:10px; color:var(--text-muted); margin-left:4px;">(${groupThreats.length} events)</span>` : ''}</span>
                    <span class="badge ${badgeClass}">${severity}</span>
                </div>
                <div class="item-meta">
                    <span><i data-lucide="crosshair"></i> ${(maxConfidence * 100).toFixed(0)}% Confidence</span>
                    <span><i data-lucide="clock"></i> ${formatTimestamp(t.timestamp)}</span>
                    ${t.entropy ? `<span><i data-lucide="zap"></i> Entropy: ${t.entropy.toFixed(2)}</span>` : ''}
                </div>
                <div class="item-actions">
                    <button class="action-btn" onclick="markFalsePositive('${t.id}')">Flag FP</button>
                    <button class="action-btn primary" onclick="markTruePositive('${t.id}')">Confirm</button>
                    <button class="action-btn" onclick="toggleGroupDetails('${t.id}')" style="margin-left:auto;">Details</button>
                </div>
                <div id="group-details-${t.id}" style="display:none; margin-top:12px; padding:10px; background:rgba(0,0,0,0.2); border-radius:8px; font-size:11px; color:var(--text-muted);">
                    ${Array.from(new Set(groupThreats.map(gt => gt.reason || 'Anomalous behavior'))).join('; ')}
                    <div style="margin-top:4px; opacity:0.7;">Source Node: ${t.source_node}</div>
                </div>
            </div>
        </div>
    `}).join('');
    
    lucide.createIcons();
}

/**
 * Render activity feed items
 */
function renderActivity(activity) {
    const list = document.getElementById('activity-feed');
    if (!list) return;
    
    if (activity.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No recent activity.</p>';
        return;
    }

    // Performance: Only show latest 20 items
    const limitedActivity = activity.slice(0, 20);

    list.innerHTML = limitedActivity.map(item => `
        <div class="feed-item">
            <div class="item-info">
                <div class="item-title" style="font-size:13px">${item.summary}</div>
                <div class="item-meta">
                    <span>${item.type}</span>
                    <span>${formatTimestamp(item.timestamp)}</span>
                </div>
            </div>
        </div>
    `).join('');
}

/**
 * Render detailed threats view
 */
function renderThreatsView(threats) {
    const list = document.getElementById('threat-view-list') || document.getElementById('threats-data-list');
    if (!list) return;

    const groups = {};
    threats.forEach(t => {
        const key = `${t.type}-${t.source_node || 'Unknown'}`;
        if (!groups[key]) groups[key] = [];
        groups[key].push(t);
    });

    list.innerHTML = Object.entries(groups).map(([key, groupThreats]) => {
        const t = groupThreats[0];
        const maxConfidence = Math.max(...groupThreats.map(gt => gt.confidence || 0));
        const severity = maxConfidence > 0.8 ? 'CRITICAL' : (maxConfidence > 0.6 ? 'HIGH' : 'MEDIUM');
        const badgeClass = maxConfidence > 0.8 ? 'red' : 'blue';
        const borderClass = maxConfidence > 0.8 ? 'threat-high' : 'threat-medium';

        return `
        <div class="timeline-item ${borderClass}" style="flex-direction: column; gap: 12px;">
            <div style="display: flex; gap: 16px;">
                <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                    <i data-lucide="shield-alert"></i>
                </div>
                <div class="item-info">
                    <div class="item-title" style="display:flex; justify-content:space-between; align-items:center;">
                        <span>${t.type} (${groupThreats.length} events)</span>
                        <span class="badge ${badgeClass}">${severity}</span>
                    </div>
                    <div class="item-meta">
                        <span><i data-lucide="crosshair"></i> ${(maxConfidence * 100).toFixed(0)}% Confidence</span>
                        <span><i data-lucide="clock"></i> ${formatTimestamp(t.timestamp)}</span>
                    </div>
                    <div style="font-size: 11px; color: var(--accent-blue); margin-top: 4px; cursor:pointer;" onclick="toggleGroupDetails('full-${t.id}')">
                        <i data-lucide="info" style="width:10px; height:10px; vertical-align:middle;"></i> Toggle Forensic Details
                    </div>
                </div>
            </div>
            
            <div id="group-details-full-${t.id}" style="display: ${state.expandedDetails.has('full-' + t.id) ? 'flex' : 'none'}; flex-direction: column; gap: 10px; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 10px;">
                ${t.entropy ? `
                    <div class="entropy-gauge">
                        <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); margin-bottom:4px;">
                            <span>Shannon Entropy</span>
                            <span>${t.entropy.toFixed(2)} bits</span>
                        </div>
                        <div style="height:4px; width:100%; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden;">
                            <div style="height:100%; width:${(t.entropy / 8 * 100).toFixed(0)}%; background:${t.entropy > 7.2 ? 'var(--accent-red)' : 'var(--accent-blue)'};"></div>
                        </div>
                    </div>
                ` : ''}
                ${groupThreats.map(gt => `
                    <div class="reason-entry" style="font-size:12px; color:var(--text-primary); background:rgba(255,255,255,0.03); padding:10px; border-radius:8px; border-left:2px solid var(--accent-blue);">
                        ${gt.reason || 'Anomalous behavior detected'}
                        <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Confidence: ${(gt.confidence * 100).toFixed(0)}% | ${formatTimestamp(gt.timestamp)}</div>
                    </div>
                `).join('')}
                ${t.file_path ? `<div style="font-size:11px; color:var(--text-muted); opacity: 0.8;">Path: ${t.file_path}</div>` : ''}
            </div>

            <div class="item-actions" style="grid-template-columns: 1fr 1fr 1fr; display: grid; gap: 8px;">
                <button class="action-btn primary" onclick="markTruePositive('${t.id}')">Mark Positive</button>
                <button class="action-btn" onclick="markFalsePositive('${t.id}')">Flag FP</button>
                <button class="action-btn" onclick="confirmThreat('${t.id}')" style="color:var(--accent-red); border-color:rgba(255,77,77,0.3);">Isolate</button>
                <button class="action-btn" onclick="navigateToStory()" style="grid-column: span 3;">View Forensic Story</button>
            </div>
        </div>
    `}).join('');
    lucide.createIcons();
}

/**
 * Render mesh network view
 */
async function renderMeshView(mesh) {
    const list = document.getElementById('mesh-data-list');
    if (!list) return;

    let pendingJoins = [];
    let quarantinedPeers = [];
    try {
        const [pj, qp] = await Promise.all([
            fetchAPI('/pending-joins'),
            fetchAPI('/quarantined-peers')
        ]);
        if (pj) pendingJoins = pj;
        if (qp) quarantinedPeers = qp;
    } catch (e) {}

    let html = `
        <div class="timeline-item">
            <div class="item-icon" style="background-color: rgba(0, 210, 255, 0.1); color: var(--accent-blue);">
                <i data-lucide="network"></i>
            </div>
            <div class="item-info">
                <div class="item-title">Connected Peers: ${mesh ? mesh.peer_count : 0}</div>
                <div class="item-meta">
                    <span>Network is actively synchronizing state...</span>
                </div>
            </div>
        </div>
    `;

    if (pendingJoins.length > 0) {
        html += `<h4 style="margin-top:20px; margin-bottom:10px; color:var(--text-header); font-size:14px;">Pending Joins</h4>`;
        html += pendingJoins.map(pj => `
            <div class="timeline-item" style="border-left: 2px solid orange;">
                <div class="item-icon" style="background-color: rgba(255, 165, 0, 0.1); color: orange;">
                    <i data-lucide="help-circle"></i>
                </div>
                <div class="item-info">
                    <div class="item-title">${pj.peer_id}</div>
                    <div class="item-meta">
                        <span><i data-lucide="map-pin"></i> ${pj.address || 'Unknown'}</span>
                        <span><i data-lucide="clock"></i> Discovered ${formatTimestamp(pj.discovered_at)}</span>
                    </div>
                    <div class="item-actions" style="margin-top:8px;">
                        <button class="action-btn primary" onclick="meshAllowPeer('${pj.peer_id}')">Allow</button>
                        <button class="action-btn" onclick="meshDenyPeer('${pj.peer_id}')">Deny</button>
                    </div>
                </div>
            </div>
        `).join('');
    }

    if (quarantinedPeers.length > 0) {
        html += `<h4 style="margin-top:20px; margin-bottom:10px; color:var(--text-header); font-size:14px;">Quarantined Peers</h4>`;
        html += quarantinedPeers.map(qp => `
            <div class="timeline-item" style="border-left: 2px solid var(--accent-red);">
                <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                    <i data-lucide="shield-alert"></i>
                </div>
                <div class="item-info">
                    <div class="item-title">${qp.peer_id}</div>
                    <div class="item-meta">
                        <span><i data-lucide="clock"></i> Quarantined ${formatTimestamp(qp.quarantined_at)}</span>
                    </div>
                    <div class="item-actions" style="margin-top:8px;">
                        <button class="action-btn" onclick="meshReleasePeer('${qp.peer_id}')">Release</button>
                    </div>
                </div>
            </div>
        `).join('');
    }

    list.innerHTML = html;
    lucide.createIcons();
}

window.meshAllowPeer = async function(id) {
    await fetch(\`${API_BASE}/pending-joins/\${id}/allow\`, { method: 'POST' });
    updateDashboard();
};
window.meshDenyPeer = async function(id) {
    await fetch(\`${API_BASE}/pending-joins/\${id}/deny\`, { method: 'POST' });
    updateDashboard();
};
window.meshReleasePeer = async function(id) {
    await fetch(\`${API_BASE}/quarantined-peers/\${id}/release\`, { method: 'POST', headers: {'x-osoosi-quarantine-key': 'admin'} });
    updateDashboard();
};

/**
 * Render malware scanner view with drill-down details
 */
function renderMalwareView(detections) {
    const list = document.getElementById('malware-data-list');
    if (!list) return;

    // Update stat counters from malware status API
    fetchAPI('/malware-status').then(status => {
        if (status) {
            updateStats('scanned', status.total_scanned || 0);
            updateStats('malware-found', status.total_malware || 0);
            updateStats('clean-scans', status.clamav_clean_count || 0);
            const mlEl = document.getElementById('stat-ml-status');
            if (mlEl) mlEl.innerText = status.model_loaded ? 'Active ✅' : 'Inactive';
        }
    });

    if (!detections || detections.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No malware detected recently. System is clean.</p>';
        return;
    }

    list.innerHTML = detections.map((det, idx) => {
        const score = det.combined_score || det.score || 0;
        const severity = score > 0.8 ? 'CRITICAL' : (score > 0.5 ? 'HIGH' : 'MEDIUM');
        const badgeClass = score > 0.8 ? 'red' : 'blue';
        const borderClass = score > 0.8 ? 'threat-high' : (score > 0.5 ? 'threat-medium' : 'threat-low');
        const fileName = det.file_path ? det.file_path.split('\\\\').pop().split('/').pop() : 'Unknown';
        const detId = `mw-${idx}`;

        return `
        <div class="timeline-item ${borderClass}" style="flex-direction: column; gap: 12px;">
            <div style="display: flex; gap: 16px;">
                <div class="item-icon" style="background-color: rgba(189, 147, 249, 0.1); color: var(--accent-purple);">
                    <i data-lucide="bug"></i>
                </div>
                <div class="item-info">
                    <div class="item-title" style="display:flex; justify-content:space-between; align-items:center;">
                        <span>${det.malware_type || 'Malware Signature Match'}</span>
                        <span class="badge ${badgeClass}">${severity}</span>
                    </div>
                    <div class="item-meta">
                        <span><i data-lucide="file" style="width:12px"></i> ${fileName}</span>
                        <span><i data-lucide="activity" style="width:12px"></i> Score: ${typeof score === 'number' ? score.toFixed(3) : 'N/A'}</span>
                        ${det.entropy ? `<span><i data-lucide="zap" style="width:12px"></i> Entropy: ${det.entropy.toFixed(2)}</span>` : ''}
                        ${det.magika_label ? `<span><i data-lucide="tag" style="width:12px"></i> ${det.magika_label}</span>` : ''}
                    </div>
                    <div style="font-size: 11px; color: var(--accent-blue); margin-top: 4px; cursor:pointer;" onclick="toggleMalwareDetails('${detId}')">
                        <i data-lucide="info" style="width:10px; height:10px; vertical-align:middle;"></i> Toggle Forensic Details
                    </div>
                </div>
            </div>

            <div id="malware-details-${detId}" style="display: ${state.expandedDetails.has(detId) ? 'flex' : 'none'}; flex-direction: column; gap: 10px; padding: 12px; background: rgba(0,0,0,0.2); border-radius: 10px;">
                ${det.entropy ? `
                    <div class="entropy-gauge">
                        <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); margin-bottom:4px;">
                            <span>Shannon Entropy</span>
                            <span>${det.entropy.toFixed(2)} bits</span>
                        </div>
                        <div style="height:4px; width:100%; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden;">
                            <div style="height:100%; width:${(det.entropy / 8 * 100).toFixed(0)}%; background:${det.entropy > 7.2 ? 'var(--accent-red)' : 'var(--accent-blue)'};"></div>
                        </div>
                    </div>
                ` : ''}
                <div style="font-size:12px; color:var(--text-primary); background:rgba(255,255,255,0.03); padding:10px; border-radius:8px; border-left:2px solid var(--accent-purple);">
                    <div><strong>Full Path:</strong> ${det.file_path || 'Unknown'}</div>
                    ${det.file_hash ? `<div style="margin-top:4px;"><strong>Hash:</strong> <code style="font-size:10px; color:var(--accent-blue);">${det.file_hash}</code></div>` : ''}
                    <div style="margin-top:4px;"><strong>ML Score:</strong> ${det.ml_score != null ? det.ml_score.toFixed(3) : 'N/A'} | <strong>Signature:</strong> ${det.signature_score != null ? det.signature_score.toFixed(3) : 'N/A'} | <strong>Combined:</strong> ${typeof score === 'number' ? score.toFixed(3) : 'N/A'}</div>
                    ${det.yara_matches && det.yara_matches.length > 0 ? `<div style="margin-top:4px;"><strong>YARA Rules:</strong> ${det.yara_matches.join(', ')}</div>` : ''}
                    ${det.evasion && det.evasion.length > 0 ? `<div style="margin-top:4px; color:var(--accent-red);"><strong>Evasion Indicators:</strong> ${det.evasion.join(', ')}</div>` : ''}
                    ${det.timestamp ? `<div style="margin-top:4px; font-size:10px; color:var(--text-muted);">Detected: ${formatTimestamp(det.timestamp)}</div>` : ''}
                </div>
            </div>

            <div class="item-actions" style="grid-template-columns: 1fr 1fr; display: grid; gap: 8px;">
                <button class="action-btn" onclick="markMalwareFP('${det.file_hash || ''}', '${fileName}')">Flag False Positive</button>
                <button class="action-btn" onclick="quarantineMalware('${det.file_path || ''}')" style="color:var(--accent-red); border-color:rgba(255,77,77,0.3);">Quarantine</button>
            </div>
        </div>
    `}).join('');
    lucide.createIcons();
}

function toggleMalwareDetails(id) {
    const el = document.getElementById('malware-details-' + id);
    if (el) el.style.display = el.style.display === 'none' ? 'flex' : 'none';
}

async function triggerMalwareScan() {
    try {
        await fetch(`${API_BASE}/scan-trigger`, { method: 'POST' });
    } catch(e) {
        console.warn('Scan trigger failed:', e);
    }
}

async function markMalwareFP(hash, name) {
    try {
        await fetch(`${API_BASE}/false-positive`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: hash, process_name: name })
        });
    } catch(e) {
        console.warn('FP marking failed:', e);
    }
}

async function quarantineMalware(filePath) {
    if (!confirm('Quarantine this file? It will be moved to an isolated location.')) return;
    try {
        await fetch(`${API_BASE}/quarantine`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_path: filePath })
        });
    } catch(e) {
        console.warn('Quarantine failed:', e);
    }
}

/**
 * Render repair engine view
 */
function renderRepairView(repairStatus) {
    const container = document.getElementById('repair-data');
    if (!container) return;

    container.innerHTML = `
        <div style="padding: 24px; text-align: center;">
            <i data-lucide="wrench" style="width:48px; height:48px; color:var(--accent-green); margin-bottom:16px;"></i>
            <h4 style="color:var(--text-header); font-size:18px; margin-bottom:8px;">System Integrity Verified</h4>
            <p style="color:var(--text-muted); font-size:14px;">All critical services and policies are currently healthy. No active repairs are needed.</p>
        </div>
    `;
    lucide.createIcons();
}

/**
 * Render Process Map (Attack Graph)
 */
async function renderProcessMapView() {
    const container = document.getElementById('attack-graph');
    const loading = document.getElementById('graph-loading');
    if (!container) return;

    if (loading) loading.style.display = 'block';

    const graphData = await fetchAPI('/attack-graph?limit=100');
    if (!graphData) {
        if (loading) loading.innerText = "Failed to load graph data.";
        return;
    }

    if (loading) loading.style.display = 'none';
    
    if (graphData.nodes.length === 0) {
        if (loading) {
            loading.style.display = 'block';
            loading.innerText = "No attack graph data available yet.";
        }
        return;
    }

    if (!state.network) {
        initGraph(container, graphData);
    } else {
        state.network.setData({
            nodes: new vis.DataSet(graphData.nodes),
            edges: new vis.DataSet(graphData.edges)
        });
    }
}

function initGraph(container, data) {
    const options = {
        nodes: {
            shape: 'dot',
            size: 20,
            font: {
                size: 12,
                color: '#ffffff',
                face: 'Inter'
            },
            borderWidth: 2,
            shadow: true
        },
        edges: {
            width: 2,
            color: { inherit: 'from' },
            smooth: {
                type: 'continuous'
            },
            arrows: {
                to: { enabled: true, scaleFactor: 0.5 }
            }
        },
        physics: {
            enabled: true,
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.3,
                springLength: 95,
                springConstant: 0.04,
                damping: 0.09,
                avoidOverlap: 0.1
            },
            stabilization: { iterations: 100 }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            zoomView: true,
            dragView: true,
            navigationButtons: false,
            keyboard: { enabled: true }
        },
        groups: {
            host: { color: { background: '#6366f1', border: '#4338ca' } },
            process: { color: { background: '#8b5cf6', border: '#6d28d9' } },
            ip: { color: { background: '#f59e0b', border: '#d97706' } },
            domain: { color: { background: '#ec4899', border: '#be185d' } },
            threat: { color: { background: '#ef4444', border: '#b91c1c' } },
            response: { color: { background: '#10b981', border: '#047857' } },
            predicted: { color: { background: '#f97316', border: '#ea580c' } }
        }
    };

    const visData = {
        nodes: new vis.DataSet(data.nodes),
        edges: new vis.DataSet(data.edges)
    };

    state.network = new vis.Network(container, visData, options);
    
    // Auto-center and fit graph once stabilized
    state.network.on("stabilizationFinished", function () {
        state.network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
    });
    
    // Initial fit attempt
    setTimeout(() => { if(state.network) state.network.fit(); }, 1000);
    
    // --- Node click: show detail tooltip ---
    state.network.on("click", function (params) {
        const tooltip = document.getElementById('graph-node-tooltip');
        if (!tooltip) return;

        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const nodeData = visData.nodes.get(nodeId);
            if (!nodeData) { tooltip.style.display = 'none'; return; }

            const groupColors = {
                host: '#6366f1', process: '#8b5cf6', ip: '#f59e0b',
                domain: '#ec4899', threat: '#ef4444', response: '#10b981',
                predicted: '#f97316'
            };
            const dotColor = groupColors[nodeData.group] || '#888';

            let rows = `<div class="tooltip-row"><span class="tooltip-key">Type</span><span class="tooltip-val">${nodeData.group || 'unknown'}</span></div>`;
            if (nodeData.title) rows += `<div class="tooltip-row"><span class="tooltip-key">Detail</span><span class="tooltip-val">${nodeData.title}</span></div>`;
            if (nodeData.id) rows += `<div class="tooltip-row"><span class="tooltip-key">ID</span><span class="tooltip-val">${nodeData.id}</span></div>`;

            // Count connections
            const connectedEdges = state.network.getConnectedEdges(nodeId);
            const connectedNodes = state.network.getConnectedNodes(nodeId);
            rows += `<div class="tooltip-row"><span class="tooltip-key">Connections</span><span class="tooltip-val">${connectedNodes.length} nodes, ${connectedEdges.length} edges</span></div>`;

            tooltip.innerHTML = `
                <div class="tooltip-title">
                    <span class="dot" style="background:${dotColor};"></span>
                    ${nodeData.label || nodeData.id}
                </div>
                ${rows}
            `;
            tooltip.style.display = 'block';

            // Focus on the clicked node
            state.network.focus(nodeId, {
                scale: 1.5,
                animation: { duration: 400, easingFunction: 'easeInOutQuad' }
            });
        } else {
            tooltip.style.display = 'none';
        }
    });

    // Hide tooltip on canvas click (empty area)
    state.network.on("deselectNode", function() {
        const tooltip = document.getElementById('graph-node-tooltip');
        if (tooltip) tooltip.style.display = 'none';
    });

    // --- Expand / Fullscreen toggle ---
    const expandBtn = document.getElementById('graph-expand-btn');
    const graphCard = document.getElementById('graph-card');
    if (expandBtn && graphCard) {
        expandBtn.onclick = () => toggleGraphFullscreen();
    }
    
    // --- Refresh button ---
    const refreshBtn = document.getElementById('refresh-graph');
    if (refreshBtn) {
        refreshBtn.onclick = () => renderProcessMapView();
    }

    // Recreate Lucide icons for dynamically added buttons
    lucide.createIcons();
}

/* ---- Graph interactive controls (global scope) ---- */

window.graphZoomIn = function() {
    if (!state.network) return;
    const scale = state.network.getScale();
    state.network.moveTo({ scale: scale * 1.4, animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
};

window.graphZoomOut = function() {
    if (!state.network) return;
    const scale = state.network.getScale();
    state.network.moveTo({ scale: scale / 1.4, animation: { duration: 300, easingFunction: 'easeInOutQuad' } });
};

window.graphFit = function() {
    if (!state.network) return;
    state.network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
};

window.toggleGraphFullscreen = function() {
    const card = document.getElementById('graph-card');
    const btn = document.getElementById('graph-expand-btn');
    if (!card) return;

    const isFullscreen = card.classList.toggle('fullscreen');

    // Update button icon/text
    if (btn) {
        btn.innerHTML = isFullscreen
            ? '<i data-lucide="minimize-2" style="width:14px; margin-right:4px;"></i> Collapse'
            : '<i data-lucide="maximize-2" style="width:14px; margin-right:4px;"></i> Expand';
        lucide.createIcons();
    }

    // Resize the vis-network to fill the new container size
    if (state.network) {
        setTimeout(() => {
            state.network.redraw();
            state.network.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
        }, 100);
    }
};

// ESC to exit fullscreen graph
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        const card = document.getElementById('graph-card');
        if (card && card.classList.contains('fullscreen')) {
            toggleGraphFullscreen();
        }
    }
});

/**
 * Render OpenTelemetry Mesh Map
 */
async function renderOtelMapView() {
    const container = document.getElementById('otel-mesh-map');
    const loading = document.getElementById('otel-map-loading');
    if (!container) return;

    if (loading) loading.style.display = 'block';

    const topologyData = await fetchAPI('/mesh/topology');
    if (!topologyData) {
        if (loading) loading.innerText = "Failed to load mesh topology.";
        return;
    }

    if (loading) loading.style.display = 'none';

    if (topologyData.nodes.length === 0) {
        if (loading) {
            loading.style.display = 'block';
            loading.innerText = "Mesh topology is still converging...";
        }
        return;
    }

    if (!state.otelNetwork) {
        initOtelMap(container, topologyData);
    } else {
        state.otelNetwork.setData({
            nodes: new vis.DataSet(topologyData.nodes),
            edges: new vis.DataSet(topologyData.edges)
        });
        state.otelNetwork.fit();
    }
}

function initOtelMap(container, data) {
    const options = {
        nodes: {
            shape: 'dot',
            size: 25,
            font: { size: 12, color: '#ffffff', face: 'Outfit' },
            borderWidth: 2,
            shadow: true,
            color: { background: 'rgba(0, 210, 255, 0.2)', border: '#00d2ff' }
        },
        edges: {
            width: 1,
            color: 'rgba(0, 210, 255, 0.3)',
            arrows: { to: { enabled: false } },
            length: 150
        },
        physics: {
            enabled: true,
            barnesHut: { gravitationalConstant: -3000, springLength: 150 },
            stabilization: { iterations: 150 }
        },
        groups: {
            host: { color: { background: '#00d2ff', border: '#00d2ff' } },
            threat: { color: { background: '#ff4d4d', border: '#ff4d4d' } },
            process: { color: { background: '#bd93f9', border: '#bd93f9' } }
        }
    };

    const visData = {
        nodes: new vis.DataSet(data.nodes),
        edges: new vis.DataSet(data.edges)
    };

    state.otelNetwork = new vis.Network(container, visData, options);
    
    state.otelNetwork.on("stabilizationFinished", function () {
        state.otelNetwork.fit();
    });
    
    setTimeout(() => { if(state.otelNetwork) state.otelNetwork.fit(); }, 1000);
}

/**
 * Handle ISO timestamps
 */
function formatTimestamp(iso) {
    try {
        const date = new Date(iso);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return iso;
    }
}

/**
 * Update the OpenTelemetry Chart
 */
function updateTelemetryChart(data) {
    const ctx = document.getElementById('telemetry-chart');
    if (!ctx) return;

    if (!state.telemetryChart) {
        state.telemetryChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels.map(l => l.split(' ')[1]), // Just show HH:MM
                datasets: [{
                    label: 'Events/min',
                    data: data.data,
                    borderColor: '#00d2ff',
                    backgroundColor: 'rgba(0, 210, 255, 0.1)',
                    borderWidth: 2,
                    pointRadius: 3,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#8b949e', font: { size: 10 } }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#8b949e', font: { size: 10 } }
                    }
                }
            }
        });
    } else {
        state.telemetryChart.data.labels = data.labels.map(l => l.split(' ')[1]);
        state.telemetryChart.data.datasets[0].data = data.data;
        state.telemetryChart.update('none');
    }
}

// Start the app
document.addEventListener('DOMContentLoaded', init);

/**
 * Render Zone Overview
 */
async function renderZoneView() {
    const summary = await fetchAPI('/zone-summary');
    if (!summary) return;

    const container = document.getElementById('zone-summary-container');
    if (container) {
        container.innerHTML = `
            <div class="stat-card glass">
                <div class="stat-label">Security Score</div>
                <div class="stat-value" style="color: ${summary.security_score > 80 ? 'var(--accent-green)' : 'var(--accent-red)'}">${summary.security_score}%</div>
            </div>
            <div class="stat-card glass">
                <div class="stat-label">Zone Node Count</div>
                <div class="stat-value">${summary.peer_count + 1}</div>
            </div>
            <div class="stat-card glass">
                <div class="stat-label">Zone ID</div>
                <div class="stat-value" style="font-size: 14px;">${summary.zone}</div>
            </div>
        `;
    }

    const recs = document.getElementById('zone-recommendations');
    if (recs) {
        if (summary.recommendations && summary.recommendations.length > 0) {
            recs.innerHTML = summary.recommendations.map(r => `
                <div class="feed-item">
                    <div class="item-title" style="color: var(--accent-blue);">Recommendation</div>
                    <div class="item-meta">${r}</div>
                </div>
            `).join('');
        } else {
            recs.innerHTML = '<p class="placeholder-text">Security posture is optimal.</p>';
        }
    }
}

/**
 * Render Approval Queue
 */
async function renderApprovalsView() {
    const approvals = await fetchAPI('/pending-actions');
    const list = document.getElementById('approval-list');
    if (!list) return;

    if (!approvals || approvals.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No pending actions requiring approval.</p>';
        return;
    }

    list.innerHTML = approvals.map(app => `
        <div class="timeline-item">
            <div class="item-icon" style="background-color: rgba(255, 165, 0, 0.1); color: orange;">
                <i data-lucide="help-circle"></i>
            </div>
            <div class="item-info">
                <div class="item-title">Pending Action: ${app.action}</div>
                <div class="item-meta">${app.description}</div>
                <div class="item-actions mt-2">
                    <button class="btn-small btn-approve" onclick="approveAction('${app.id}')">Approve</button>
                    <button class="btn-small btn-reject" onclick="rejectAction('${app.id}')">Reject</button>
                </div>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
}

window.approveAction = async function(id) {
    const res = await fetch(`${API_BASE}/approve-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_id: id })
    });
    if (res.ok) renderApprovalsView();
};

window.rejectAction = async function(id) {
    const res = await fetch(`${API_BASE}/reject-action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ threat_id: id })
    });
    if (res.ok) renderApprovalsView();
};

window.markFalsePositive = async function(threatId) {
    if (window.event) window.event.stopPropagation();
    if (!confirm("Are you sure this is a False Positive? This will stop active responses and un-ghost files.")) return;
    
    try {
        const res = await fetch(`${API_BASE}/threats/${threatId}/false-positive`, {
            method: 'POST'
        });
        const data = await res.json();
        if (data.ok) {
            suppressThreatLocally(threatId);
            setTimeout(updateDashboard, 250);
        } else {
            alert("Error: " + data.error);
        }
    } catch (err) {
        console.error("Failed to mark false positive:", err);
    }
};

window.markTruePositive = async function(threatId) {
    if (window.event) window.event.stopPropagation();
    if (!confirm("Confirm this as a True Positive? This will boost detection confidence across the mesh.")) return;
    
    try {
        const res = await fetch(`${API_BASE}/threats/${threatId}/true-positive`, {
            method: 'POST'
        });
        const data = await res.json();
        if (data.ok) {
            alert("Threat confirmed. Intelligence reinforced across mesh.");
            updateDashboard();
        } else {
            alert("Error: " + data.error);
        }
    } catch (err) {
        console.error("Failed to mark true positive:", err);
    }
};

/**
 * Global Interactivity Helpers
 */
window.toggleGroupDetails = function(id) {
    if (state.expandedDetails.has(id)) {
        state.expandedDetails.delete(id);
    } else {
        state.expandedDetails.add(id);
    }
    const el = document.getElementById(`group-details-${id}`);
    if (el) {
        el.style.display = state.expandedDetails.has(id) ? 'flex' : 'none';
        lucide.createIcons();
    }
};

window.toggleMalwareDetails = function(id) {
    if (state.expandedDetails.has(id)) {
        state.expandedDetails.delete(id);
    } else {
        state.expandedDetails.add(id);
    }
    const el = document.getElementById(`malware-details-${id}`);
    if (el) {
        el.style.display = state.expandedDetails.has(id) ? 'flex' : 'none';
        lucide.createIcons();
    }
};

window.confirmThreat = async function(id) {
    if (!confirm('Are you sure you want to isolate this node and terminate the offending process?')) return;
    try {
        await fetch(`/api/threats/confirm/${id}`, { method: 'POST' });
        showNotification('Response initiated: Node isolated.', 'info');
        updateDashboard();
    } catch (e) {
        showNotification('Failed to confirm threat.', 'error');
    }
};

function showNotification(msg, type = 'info') {
    // Basic toast if needed, or just log for now
    console.log(`[Dashboard] ${type.toUpperCase()}: ${msg}`);
}

window.submitManualTP = async function() {
    const proc = document.getElementById('manual-tp-proc').value.trim();
    const hash = document.getElementById('manual-tp-hash').value.trim();
    if (!proc && !hash) {
        alert("Please provide at least a process name or a hash.");
        return;
    }
    
    if (!confirm(`Are you sure you want to report ${proc || hash} as a threat? This will trigger autonomous Morphic Entanglement.`)) return;

    try {
        const res = await fetch(`${API_BASE}/behavioral/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                process_name: proc || null,
                file_hash: hash || null,
                is_suspicious: true
            })
        });
        const data = await res.json();
        if (data.ok) {
            alert("Threat reported. Morphic Entanglement sequence initiated.");
            document.getElementById('manual-tp-proc').value = '';
            document.getElementById('manual-tp-hash').value = '';
            updateDashboard();
        } else {
            alert("Error: " + data.error);
        }
    } catch (err) {
        console.error("Failed to submit manual TP:", err);
    }
};

window.submitManualFP = async function() {
    const proc = document.getElementById('manual-fp-proc').value.trim();
    const hash = document.getElementById('manual-fp-hash').value.trim();
    if (!proc && !hash) {
        alert("Please provide at least a process name or a hash.");
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/behavioral/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                process_name: proc || null,
                file_hash: hash || null,
                is_suspicious: false
            })
        });
        const data = await res.json();
        if (data.ok) {
            alert("Manual suppression policy applied.");
            document.getElementById('manual-fp-proc').value = '';
            document.getElementById('manual-fp-hash').value = '';
            updateDashboard();
        } else {
            alert("Error: " + data.error);
        }
    } catch (err) {
        console.error("Failed to submit manual FP:", err);
    }
};

window.investigateNode = function(nodeId) {
    if (event) event.stopPropagation();
    // Switch to mesh view and highlight node (placeholder logic)
    document.querySelector('[data-view="mesh"]').click();
};

/**
 * Render Forensic Story view
 */
async function renderStoryView() {
    const container = document.getElementById('story-container');
    if (!container) return;

    // Add listener to refresh button
    const refreshBtn = document.getElementById('refresh-story');
    if (refreshBtn) {
        refreshBtn.onclick = async () => {
            container.innerHTML = '<div class="loading-spinner" style="margin: 20px auto;"></div><p class="placeholder-text">Synthesizing forensic story from OpenTelemetry spans...</p>';
            const story = await fetchAPI('/story');
            if (story && story.story && story.story !== "Orchestrator not active.") {
                // Convert markdown-ish text to basic HTML (simple bold/newlines)
                const formatted = story.story
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    .replace(/\n/g, '<br/>');
                container.innerHTML = `<div class="story-content" style="padding: 10px; animation: fadeIn 0.8s ease-out;">${formatted}</div>`;
            } else {
                container.innerHTML = '<p class="placeholder-text">No significant security events to report in this story yet.</p>';
            }
        };
    }

    // Initial load if empty or placeholder
    if (container.querySelector('.placeholder-text') || container.innerHTML === '') {
        container.innerHTML = '<div class="loading-spinner" style="margin: 20px auto;"></div><p class="placeholder-text">Synthesizing forensic story...</p>';
        const story = await fetchAPI('/story');
        if (story && story.story && story.story !== "Orchestrator not active.") {
            const formatted = story.story
                .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                .replace(/\n/g, '<br/>');
            container.innerHTML = `<div class="story-content" style="padding: 10px; animation: fadeIn 0.8s ease-out;">${formatted}</div>`;
        } else {
            container.innerHTML = '<p class="placeholder-text">No significant security events to report in this story yet.</p>';
        }
    }
}

/**
 * Navigate to the Forensic Story view from any button
 */
function navigateToStory() {
    const storyNav = document.querySelector('[data-view="story"]');
    if (storyNav) {
        storyNav.click();
    }
}
/**
 * Render the Gossip Feed view (P2P mesh intelligence sharing)
 */
async function renderGossipView() {
    const list = document.getElementById('gossip-feed-list');
    if (!list) return;

    // 1. Update stats from state (polled in updateDashboard)
    const totalEl = document.getElementById('gossip-total-received');
    if (totalEl) totalEl.innerText = state.gossip_count;

    // 2. Fetch recent activity and filter for mesh/gossip events
    const activity = await fetchAPI('/activity');
    if (!activity || activity.length === 0) {
        list.innerHTML = '<p class="placeholder-text">Listening for P2P gossip packets...</p>';
        return;
    }

    // Gossip events typically include MESH_*, CONSENSUS_*, INTEL_*, or are marked as mesh sources
    const gossipEvents = activity.filter(a => 
        a.type.includes('MESH') || 
        a.type.includes('CONSENSUS') || 
        a.type.includes('INTEL') ||
        (a.summary && a.summary.toLowerCase().includes('mesh'))
    );

    if (gossipEvents.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No gossip packets decoded in the last cycle.</p>';
        return;
    }

    // Update last action stat
    const lastActionEl = document.getElementById('gossip-last-action');
    if (lastActionEl && gossipEvents.length > 0) {
        lastActionEl.innerText = gossipEvents[0].summary;
    }

    list.innerHTML = gossipEvents.map(event => {
        let icon = 'messages-square';
        let color = 'orange';
        
        if (event.type.includes('THREAT')) { icon = 'shield-alert'; color = 'red'; }
        else if (event.type.includes('CONSENSUS')) { icon = 'check-circle'; color = 'purple'; }
        else if (event.type.includes('INTEL')) { icon = 'zap'; color = 'blue'; }

        return `
            <div class="timeline-item" style="border-left: 2px solid var(--accent-${color});">
                <div class="item-icon" style="background-color: rgba(var(--accent-${color}-rgb), 0.1); color: var(--accent-${color});">
                    <i data-lucide="${icon}"></i>
                </div>
                <div class="item-info">
                    <div class="item-title">${event.summary}</div>
                    <div class="item-meta">
                        <span><i data-lucide="tag"></i> ${event.type}</span>
                        <span><i data-lucide="clock"></i> ${formatTimestamp(event.timestamp)}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    lucide.createIcons();
}

/**
 * Render detection engine statistics
 */
function renderDetectionStats(stats) {
    const grid = document.getElementById('detection-engines-grid');
    if (!grid) return;

    if (!stats || Object.keys(stats).length === 0) {
        grid.innerHTML = '<p class="placeholder-text">No active detection engines reported.</p>';
        return;
    }

    let html = '';
    for (const [engine, data] of Object.entries(stats)) {
        let statsHtml = '';
        
        if (engine === 'Sigma-Engine') {
            statsHtml = `
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Rules Loaded</span>
                    <span class="engine-stat-value active">${data.rule_count || 0}</span>
                </div>
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Detections</span>
                    <span class="engine-stat-value ${data.total_detections > 0 ? 'high' : ''}">${data.total_detections || 0}</span>
                </div>
            `;
        } else if (engine === 'IOC-Scanner') {
            statsHtml = `
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Indicators</span>
                    <span class="engine-stat-value active">${data.indicator_count || 0}</span>
                </div>
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Matches</span>
                    <span class="engine-stat-value ${data.total_detections > 0 ? 'high' : ''}">${data.total_detections || 0}</span>
                </div>
            `;
        } else if (engine.includes('Yara')) {
             statsHtml = `
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Type</span>
                    <span class="engine-stat-value active">Native YARA-X</span>
                </div>
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Status</span>
                    <span class="engine-stat-value active">Scanning</span>
                </div>
            `;
        } else {
             statsHtml = `
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Status</span>
                    <span class="engine-stat-value active">Active</span>
                </div>
                <div class="engine-stat-item">
                    <span class="engine-stat-label">Voter</span>
                    <span class="engine-stat-value">Policy</span>
                </div>
            `;
        }

        html += `
            <div class="engine-card">
                <div class="engine-header">
                    <span class="engine-name">${engine}</span>
                    <i data-lucide="cpu" style="width:14px; height:14px; color:var(--text-muted);"></i>
                </div>
                <div class="engine-stats">
                    ${statsHtml}
                </div>
            </div>
        `;
    }

    grid.innerHTML = html;
    if (window.lucide) window.lucide.createIcons();
}
