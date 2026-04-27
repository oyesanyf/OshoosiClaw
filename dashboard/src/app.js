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
    telemetryChart: null
};

/**
 * Initialize Lucide icons and start polling
 */
function init() {
    setupNav();
    setupSearch();
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
    try {
        const [status, threats, mesh, activity, malwareDetections, repairStatus, telemetryData] = await Promise.all([
            fetchAPI('/status'),
            fetchAPI('/threats'),
            fetchAPI('/mesh-stats'),
            fetchAPI('/activity'),
            fetchAPI('/malware-detections'),
            fetchAPI('/repair-status'),
            fetchAPI('/telemetry/timeseries')
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
            state.threats = visibleThreats;
            updateStats('threat-count', visibleThreats.length);
            renderThreats(visibleThreats);
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

        if (telemetryData) {
            updateTelemetryChart(telemetryData);
        }

        // Render views
        if (state.current_view === 'threats' && threats) {
            renderThreatsView(state.threats);
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

    const filtered = threats.filter(t => {
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
    filtered.forEach(t => {
        // Variation is defined by Type + Source only; reasons are listed inside
        const key = `${t.type}-${t.source_node || 'Unknown'}`;
        if (!groups[key]) groups[key] = [];
        groups[key].push(t);
    });

    list.innerHTML = Object.entries(groups).map(([key, groupThreats]) => {
        const t = groupThreats[0];
        const maxConfidence = Math.max(...groupThreats.map(gt => gt.confidence || 0));
        const severity = maxConfidence > 0.8 ? 'CRITICAL' : (maxConfidence > 0.6 ? 'HIGH' : 'MEDIUM');
        const severityColor = maxConfidence > 0.8 ? 'var(--accent-red)' : (maxConfidence > 0.6 ? '#ff9900' : '#ffcc00');
        
        return `
        <div class="timeline-item">
            <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                <i data-lucide="shield-alert"></i>
            </div>
            <div class="item-info">
                <div class="item-title" style="display:flex; justify-content:space-between; align-items:center;">
                    <span>${t.type} ${groupThreats.length > 1 ? `<span style="font-size:10px; color:var(--text-muted); margin-left:4px;">(${groupThreats.length} events)</span>` : ''}</span>
                    <span style="font-size:9px; padding:1px 5px; border-radius:4px; background:${severityColor}; color:white; vertical-align:middle;">${severity}</span>
                </div>
                <div class="item-meta">
                    <span><i data-lucide="crosshair" style="width:12px"></i> ${(maxConfidence * 100).toFixed(0)}% Confidence</span>
                    <span><i data-lucide="clock" style="width:12px"></i> ${formatTimestamp(t.timestamp)}</span>
                    ${t.entropy ? `<span><i data-lucide="zap" style="width:12px"></i> Entropy: ${t.entropy.toFixed(2)}</span>` : ''}
                </div>
                <div class="item-details" style="font-size: 11px; margin-top: 4px; color: var(--text-muted);">
                    ${Array.from(new Set(groupThreats.map(gt => gt.reason || 'Anomalous behavior'))).join('; ')}
                    <br/>
                    <span style="font-size: 10px; opacity: 0.8;">Source: ${t.source_node}</span>
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
        const severity = maxConfidence > 0.8 ? 'CRITICAL SEVERITY' : (maxConfidence > 0.6 ? 'HIGH SEVERITY' : 'MEDIUM SEVERITY');
        const severityColor = maxConfidence > 0.8 ? 'var(--accent-red)' : (maxConfidence > 0.6 ? '#ff9900' : '#ffcc00');

        return `
        <div class="timeline-item group-item" style="margin-bottom: 20px; border-bottom: 1px solid var(--glass-border); padding-bottom: 16px;">
            <div class="item-icon" style="background-color: rgba(255, 77, 77, 0.1); color: var(--accent-red);">
                <i data-lucide="shield-alert"></i>
            </div>
            <div class="item-info" style="cursor: pointer;" onclick="const d = document.getElementById('panel-long-${t.id}'); d.style.display = d.style.display === 'none' ? 'flex' : 'none';">
                <div class="item-title" style="font-size: 16px; font-weight: 600;">
                    ${t.type} 
                    <span style="font-size:10px; padding:2px 8px; border-radius:12px; background:${severityColor}; color:white; margin-left:12px; vertical-align: middle;">${severity}</span>
                </div>
                <div class="item-meta" style="margin: 8px 0;">
                    <span><i data-lucide="crosshair" style="width:12px"></i> Max Confidence: ${(maxConfidence * 100).toFixed(0)}%</span>
                    <span><i data-lucide="clock" style="width:12px"></i> Latest: ${formatTimestamp(t.timestamp)}</span>
                    <span><i data-lucide="target" style="width:12px"></i> Source: ${t.source_node || 'Unknown'}</span>
                </div>
                <div style="font-size: 11px; color: var(--accent-blue); margin-top: 4px;">Click to expand details</div>
                <div id="panel-long-${t.id}" class="group-reasons" style="display: none; flex-direction: column; gap: 8px; margin-top: 12px;">
                    ${t.entropy ? `
                        <div class="entropy-gauge" style="margin-bottom: 10px; background: rgba(255,255,255,0.05); padding: 10px; border-radius: 6px;">
                            <div style="display:flex; justify-content:space-between; font-size:10px; color:var(--text-muted); margin-bottom:4px;">
                                <span>Shannon Entropy</span>
                                <span>${t.entropy.toFixed(2)} bits</span>
                            </div>
                            <div style="height:4px; width:100%; background:rgba(255,255,255,0.1); border-radius:2px; overflow:hidden;">
                                <div style="height:100%; width:${(t.entropy / 8 * 100).toFixed(0)}%; background:${t.entropy > 7.2 ? 'var(--accent-red)' : 'var(--accent-blue)'};"></div>
                            </div>
                            <div style="font-size:9px; color:var(--text-muted); margin-top:4px;">
                                ${t.entropy > 7.2 ? 'High entropy indicates potential encryption or packing.' : 'Low/Medium entropy suggests standard binary code.'}
                            </div>
                        </div>
                    ` : ''}
                    ${groupThreats.map(gt => `
                        <div class="reason-entry" style="font-size:12px; color:var(--text-header); background:rgba(255,255,255,0.03); padding:10px; border-radius:6px; border-left:3px solid ${severityColor};">
                            <div style="font-weight: 600; margin-bottom: 2px;">Detection Signal:</div>
                            ${gt.reason || 'Anomalous behavior detected'}
                            <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Confidence: ${(gt.confidence * 100).toFixed(0)}% | ${formatTimestamp(gt.timestamp)}</div>
                        </div>
                    `).join('')}
                    ${t.file_path ? `<div style="font-size:11px; color:var(--text-muted); margin-top:10px; opacity: 0.8;">Primary Path: ${t.file_path}</div>` : ''}
                </div>
            </div>
            <div class="item-actions" style="display:flex; flex-direction: column; gap: 8px; justify-content: center; min-width: 150px;">
                <button class="btn-text" onclick="markTruePositive('${t.id}')" style="color:var(--accent-green); border:1px solid var(--accent-green); padding:8px 16px; border-radius:6px; width: 100%; background: rgba(0, 255, 150, 0.05); transition: all 0.2s;">Mark Positive</button>
                <button class="btn-text" onclick="markFalsePositive('${t.id}')" style="color:var(--text-muted); border:1px solid var(--glass-border); padding:8px 16px; border-radius:6px; width: 100%; transition: all 0.2s;">Mark as False Positive</button>
                <button class="btn-text" onclick="confirmThreat('${t.id}')" style="color:var(--accent-red); border:1px solid var(--accent-red); padding:8px 16px; border-radius:6px; width: 100%; background: rgba(255, 77, 77, 0.05); transition: all 0.2s;">Confirm & Isolate</button>
                <button class="btn-text" onclick="document.querySelector('[data-view=\'story\']').click()" style="color:var(--text-header); border:1px solid var(--glass-border); padding:8px 16px; border-radius:6px; width: 100%; background: rgba(255, 255, 255, 0.05);">Forensic Story</button>
            </div>
        </div>
    `}).join('');
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
                    ${det.entropy ? `<span><i data-lucide="zap" style="width:12px"></i> Entropy: ${det.entropy.toFixed(2)}</span>` : ''}
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
        state.network.fit();
    });
    
    // Initial fit attempt
    setTimeout(() => { if(state.network) state.network.fit(); }, 1000);
    
    // Add event listener for refreshing
    const refreshBtn = document.getElementById('refresh-graph');
    if (refreshBtn) {
        refreshBtn.onclick = () => renderProcessMapView();
    }
}

/**
 * Render OpenTelemetry Mesh Map
 */
async function renderOtelMapView() {
    const container = document.getElementById('otel-mesh-map');
    const loading = document.getElementById('otel-map-loading');
    if (!container) return;

    if (loading) loading.style.display = 'block';

    const topologyData = await fetchAPI('/mesh/topology');
    setTimeout(() => { if(state.network) state.network.fit(); }, 1000);
    
    // Add event listener for refreshing
    const refreshBtn = document.getElementById('refresh-graph');
    if (refreshBtn) {
        refreshBtn.onclick = () => renderProcessMapView();
    }
}

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

window.confirmThreat = async function(threatId) {
    if (window.event) window.event.stopPropagation();
    try {
        const res = await fetch(`${API_BASE}/triage/decide`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ threat_id: threatId, action: 'Isolate' })
        });
        const data = await res.json();
        if (data.ok) {
            alert("Threat confirmed. Isolation initiated.");
            updateDashboard();
        }
    } catch (err) {
        console.error("Failed to confirm threat:", err);
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
