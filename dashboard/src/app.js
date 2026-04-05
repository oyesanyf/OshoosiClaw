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
            if (view === 'dashboard') {
                document.getElementById('dashboard-view').classList.add('active');
                document.getElementById('other-view').classList.remove('active');
                viewTitle.innerText = "Detection Overview";
            } else {
                document.getElementById('dashboard-view').classList.remove('active');
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
        const [status, threats, mesh, activity] = await Promise.all([
            fetchAPI('/status'),
            fetchAPI('/threats'),
            fetchAPI('/mesh-stats'),
            fetchAPI('/activity')
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
        }

        if (activity) {
            state.activity = activity;
            renderActivity(activity);
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
