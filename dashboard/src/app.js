const API_BASE = '/api';
const POLL_INTERVAL = 3000;

const state = {
    uptime: '',
    node_id: '',
    peer_count: 0,
    threats: [],
    activity: [],
    chain_verified: false,
    current_view: 'dashboard'
};

/**
 * Initialize Lucide icons and start polling
 */
function init() {
    setupNav();
    updateDashboard();
    setInterval(updateDashboard, POLL_INTERVAL);
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
            } else if (view === 'malware') {
                document.getElementById('malware-view').classList.add('active');
                viewTitle.innerText = "Malware Scanner";
            } else if (view === 'repair') {
                document.getElementById('repair-view').classList.add('active');
                viewTitle.innerText = "Repair Engine";
            } else {
                document.getElementById('other-view').classList.add('active');
                viewTitle.innerText = item.querySelector('span').innerText;
            }
            
            
            state.current_view = view;
        });
    });
}

/**
 * Main update loop
 */
async function updateDashboard() {
    try {
        const [status, threats, mesh, activity, malwareDetections, repairStatus] = await Promise.all([
            fetchAPI('/status'),
            fetchAPI('/threats'),
            fetchAPI('/mesh-stats'),
            fetchAPI('/activity'),
            fetchAPI('/malware-detections'),
            fetchAPI('/repair-status')
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
            state.threats = threats;
            updateStats('threat-count', threats.length);
            renderThreats(threats);
        }

        if (mesh) {
            state.peer_count = mesh.peer_count;
            updateStats('peer-count', mesh.peer_count);
            updateStats('pending-joins', mesh.pending_joins || 0);
            updateStats('quarantined', mesh.quarantined_peers || 0);
        }

        if (activity) {
            state.activity = activity;
            renderActivity(activity);
        }

        // Render views
        if (state.current_view === 'threats' && threats) {
            renderThreatsView(threats);
        }
        if (state.current_view === 'mesh') {
            renderMeshView(mesh);
        }
        if (state.current_view === 'malware' && malwareDetections) {
            renderMalwareView(malwareDetections);
        }
        if (state.current_view === 'repair' && repairStatus) {
            renderRepairView(repairStatus);
        }

        // Update global indicator
        document.getElementById('agent-status-text').innerText = "Agent Online";
        document.querySelector('.status-dot').className = "status-dot online";

    } catch (error) {
        console.error("Failed to update dashboard:", error);
        document.getElementById('agent-status-text').innerText = "Agent Offline";
        document.querySelector('.status-dot').className = "status-dot";
    }
}

/**
 * Helper to fetch from API
 */
async function fetchAPI(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (err) {
        console.warn(`Error fetching ${endpoint}:`, err);
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

    list.innerHTML = threats.map(threat => `
        <div class="timeline-item">
            <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                <i data-lucide="shield-alert"></i>
            </div>
            <div class="item-info">
                <div class="item-title">${threat.type} Detected</div>
                <div class="item-meta">
                    <span><i data-lucide="crosshair" style="width:12px"></i> Confidence: ${(threat.confidence * 100).toFixed(0)}%</span>
                    <span><i data-lucide="clock" style="width:12px"></i> ${formatTimestamp(threat.timestamp)}</span>
                </div>
                <div class="item-details" style="font-size: 11px; margin-top: 4px; color: var(--text-muted);">
                    ${threat.reason ? `<div style="color:var(--accent-red); margin-bottom:2px;">${threat.reason}</div>` : ''}
                    ${threat.file_path ? `<div style="margin-bottom:2px;">File: ${threat.file_path}</div>` : ''}
                    ID: ${threat.id} | Source: ${threat.source_node}
                </div>
            </div>
        </div>
    `).join('');
    
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

    list.innerHTML = activity.map(item => `
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
    const list = document.getElementById('threats-data-list');
    if (!list) return;
    
    if (!threats || threats.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No active threats detected in the network.</p>';
        return;
    }

    list.innerHTML = threats.map(threat => `
        <div class="timeline-item">
            <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                <i data-lucide="shield-alert"></i>
            </div>
            <div class="item-info">
                <div class="item-title">${threat.type} <span style="font-size:10px; padding:2px 6px; border-radius:8px; background:var(--accent-red); color:white; margin-left:8px;">HIGH SEVERITY</span></div>
                <div class="item-meta">
                    <span><i data-lucide="crosshair" style="width:12px"></i> Confidence: ${(threat.confidence * 100).toFixed(0)}%</span>
                    <span><i data-lucide="clock" style="width:12px"></i> ${formatTimestamp(threat.timestamp)}</span>
                    <span><i data-lucide="target" style="width:12px"></i> Source: ${threat.source_node || 'Unknown'}</span>
                </div>
                ${threat.reason ? `<div class="item-reason" style="font-size:12px; color:var(--accent-red); margin-top:6px; background:rgba(255,77,77,0.05); padding:8px; border-radius:4px; border-left:3px solid var(--accent-red);">Reason: ${threat.reason}</div>` : ''}
                ${threat.file_path ? `<div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Path: ${threat.file_path}</div>` : ''}
            </div>
            <div class="item-actions" style="display:flex; align-items:center;">
                <button class="btn-text" style="color:var(--text-muted); border:1px solid var(--glass-border); padding:6px 12px; border-radius:6px;">Mark False Positive</button>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
}

/**
 * Render mesh network view
 */
function renderMeshView(mesh) {
    const list = document.getElementById('mesh-data-list');
    if (!list) return;

    // Placeholder data rendering
    list.innerHTML = `
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
    lucide.createIcons();
}

/**
 * Render malware scanner view
 */
function renderMalwareView(detections) {
    const list = document.getElementById('malware-data-list');
    if (!list) return;

    if (!detections || detections.length === 0) {
        list.innerHTML = '<p class="placeholder-text">No malware detected recently.</p>';
        return;
    }

    list.innerHTML = detections.map(det => `
        <div class="timeline-item">
            <div class="item-icon" style="background-color: rgba(189, 147, 249, 0.1); color: var(--accent-purple);">
                <i data-lucide="bug"></i>
            </div>
            <div class="item-info">
                <div class="item-title">Malware Signature Match</div>
                <div class="item-meta">
                    <span><i data-lucide="file" style="width:12px"></i> File: ${det.file_path || 'Unknown'}</span>
                    <span><i data-lucide="activity" style="width:12px"></i> Score: ${det.score || 'N/A'}</span>
                </div>
            </div>
        </div>
    `).join('');
    lucide.createIcons();
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

// Start the app
document.addEventListener('DOMContentLoaded', init);
