/**
 * X-NIDS SOC — Dashboard Logic
 * Handles metrics polling and rendering of core dashboard pages.
 */

window.charts = {};
const GRID = { color: "rgba(255,255,255,.04)" };
const MAX_PTS = 60;
const POLL_MS = 1000;

const BASE = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    transitions: { active: { animation: { duration: 400 } } },
    plugins: { legend: { display: false } },
};

let DATA = { summary: {}, history: [], alerts: [], top_ips: [], top_ports: [], current_window: {} };

const IC = {
    pps: `<svg class="mc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    total: `<svg class="mc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 2l-4 5-4-5"/></svg>`,
    bw: `<svg class="mc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20V4M4 12l8-8 8 8"/></svg>`,
    ips: `<svg class="mc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="7" r="4"/><path d="M5.5 21a7.5 7.5 0 0 1 13 0"/></svg>`,
    alert: `<svg class="mc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`,
    threat: `<svg class="mc-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
};

function classIcon(cls) {
    if (cls === "port_scan") return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`;
    if (cls === "packet_flood") return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
    if (cls === "brute_force") return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
    return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
}

function destroyCharts() {
    Object.keys(window.charts).forEach(k => {
        if (window.charts[k]) window.charts[k].destroy();
        delete window.charts[k];
    });
}

function makeChart(id, cfg) {
    const el = document.getElementById(id);
    if (!el) return null;
    window.charts[id] = new Chart(el, cfg);
    return window.charts[id];
}

function streamChart(cid, l, d, delta) {
    const c = window.charts[cid];
    if (!c || delta <= 0) return;
    const ds = c.data;
    for (let i = l.length - delta; i < l.length; i++) {
        ds.labels.push(l[i]);
        ds.datasets[0].data.push(d[i]);
    }
    while (ds.labels.length > MAX_PTS) {
        ds.labels.shift();
        ds.datasets[0].data.shift();
    }
    c.update("none");
}

// ── Pages ──

function renderDashboard() {
    destroyCharts();
    const d = DATA || {};
    const s = d.summary || {};
    const tl = d.threat_level || {};
    const cw = d.current_window || {};
    const hist = d.history || [];

    let labels = hist.map(h => h.timestamp);
    let ppsData = hist.map(h => h.packet_rate);
    let portsData = hist.map(h => h.unique_ports);

    const main = document.getElementById("main");
    main.innerHTML = `
    <div class="metric-row">
        <div class="metric-card">${IC.pps}<div class="mc-label">Packet Rate</div><div class="mc-value" id="mc-pps">${cw.packet_rate || 0}</div></div>
        <div class="metric-card">${IC.total}<div class="mc-label">Total Packets</div><div class="mc-value" id="mc-total">${fmt(s.total_packets || 0)}</div></div>
        <div class="metric-card">${IC.bw}<div class="mc-label">Bandwidth</div><div class="mc-value" id="mc-bw">${s.bandwidth || '0 B'}</div></div>
        <div class="metric-card">${IC.ips}<div class="mc-label">Unique IPs</div><div class="mc-value" id="mc-ips">${s.unique_src_ips || 0}</div></div>
        <div class="metric-card">${IC.alert}<div class="mc-label">Active Alerts</div><div class="mc-value" id="mc-alerts" style="color:var(--red)">${s.active_alerts || 0}</div></div>
        <div class="metric-card">${IC.threat}<div class="mc-label">Threat Score</div><div class="mc-value" id="mc-threat" style="color:${tCol(tl.score || 0)}">${tl.score || 0}%</div></div>
    </div>
    
    <div class="grid-2">
        <div class="card"><div class="card-header">Traffic Rate</div>
            <div class="chart-wrap"><canvas id="c-pps"></canvas></div></div>
        <div class="card"><div class="card-header">Unique Ports</div>
            <div class="chart-wrap"><canvas id="c-ports"></canvas></div></div>
    </div>
    <div class="card" style="padding:0">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 20px 0;">
            <div class="card-header" style="margin:0;padding:0;border:none;">Recent Alerts</div>
            <button onclick="navigate('alerts')" class="filter-btn">View All</button>
        </div>
        <div id="dash-alerts" class="alert-feed" style="padding:16px 20px 20px"><p class="empty-msg">No alerts detected.</p></div>
    </div>`;

    setTimeout(() => {
        makeChart("c-pps", { type: "line", data: { labels: labels, datasets: [{ label: "PPS", data: ppsData, borderColor: "#3b82f6", backgroundColor: "rgba(59,130,246,.1)", fill: true, tension: 0.3, pointRadius: 0 }] }, options: { ...BASE, scales: { x: { display: false }, y: { grid: GRID, beginAtZero: true } } } });
        makeChart("c-ports", { type: "line", data: { labels: labels, datasets: [{ label: "Ports", data: portsData, borderColor: "#10b981", backgroundColor: "rgba(16,185,129,.1)", fill: true, tension: 0.3, pointRadius: 0 }] }, options: { ...BASE, scales: { x: { display: false }, y: { grid: GRID, beginAtZero: true } } } });
        renderAlertList("dash-alerts", (d.alerts || []).slice(0, 5));
    }, 50);
}

function renderAlertList(containerId, alerts) {
    const c = document.getElementById(containerId);
    if (!c) return;
    if (!alerts || !alerts.length) { c.innerHTML = `<p class="empty-msg">No alerts detected.</p>`; return; }

    c.innerHTML = alerts.map(a => `
    <div class="alert-card ${sevClass(a.severity)}">
        <div class="a-header">
            <span class="a-badge">${a.severity}</span>
            <div class="a-body">
                <div class="a-title">${classIcon(a.classification)} ${a.attack_type}</div>
                <div class="a-meta"><span class="td-ip">${a.source_ip}</span> · ${a.timestamp} · Target Ports: ${a.unique_ports} · ${riskHTML(a.risk_score)}</div>
            </div>
            ${a.mitre?.technique_id && a.mitre?.technique_id !== 'N/A' ? `<a href="${a.mitre?.url}" target="_blank" class="mitre-tag">${a.mitre?.technique_id}</a>` : ''}
        </div>
        <div class="a-desc"><ul>${(a.explanation || []).map(e => `<li>${e}</li>`).join('')}</ul></div>
    </div>`).join('');
}

function renderAlerts() {
    destroyCharts();
    const main = document.getElementById("main");
    main.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:20px;">
        <div><div class="page-title" style="margin-bottom:12px">Alert Console</div>
             <div class="filter-bar"><button class="filter-btn active" data-f="all">All</button><button class="filter-btn" data-f="critical">Critical</button><button class="filter-btn" data-f="high">High</button><button class="filter-btn" data-f="medium">Medium</button></div></div>
        <input type="text" id="alertSearch" class="search-input" placeholder="Search IP or Alert Type..." value="">
    </div>
    <div id="alertsFeed" class="alert-feed"><p class="empty-msg">No alerts detected.</p></div>`;

    document.querySelectorAll(".filter-btn").forEach(b => {
        b.addEventListener("click", () => {
            document.querySelectorAll(".filter-btn").forEach(x => x.classList.remove("active"));
            b.classList.add("active");
            updateAlertsFeed();
        });
    });
    const se = document.getElementById("alertSearch");
    if (se) se.addEventListener("input", () => { updateAlertsFeed(); });
    updateAlertsFeed();
}

function updateAlertsFeed() {
    if (currentPage !== "alerts") return;
    const feed = document.getElementById("alertsFeed");
    const filter = document.querySelector(".filter-btn.active")?.dataset.f || "all";
    const search = document.getElementById("alertSearch")?.value.toLowerCase() || "";
    if (!feed) return;
    let a = DATA?.alerts || [];
    if (filter !== "all") a = a.filter(x => x.severity.toLowerCase() === filter);
    if (search) a = a.filter(x => (x.source_ip || "").includes(search) || (x.attack_type || "").toLowerCase().includes(search));
    renderAlertList("alertsFeed", a);
}

function renderAnalysis() {
    destroyCharts();
    const main = document.getElementById("main");
    main.innerHTML = `
    <div class="page-title">Traffic Analysis</div>
    <div class="grid-2" style="grid-template-columns:2fr 1fr;">
        <div class="card"><div class="card-header">Live Packet Rate</div><div class="chart-wrap"><canvas id="a-pps"></canvas></div></div>
        <div class="card"><div class="card-header">Protocol Distribution</div><div class="chart-wrap"><canvas id="a-proto"></canvas></div></div>
    </div>
    <div class="grid-2" style="grid-template-columns:1fr 2fr;">
        <div class="card"><div class="card-header">Top Targeted Ports</div><div class="chart-wrap"><canvas id="a-topports"></canvas></div></div>
        <div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>Source IP</th><th>Packets</th><th>Ports</th><th>Risk</th></tr></thead><tbody id="a-iptable"><tr><td colspan="4" class="empty-row">Checking tables...</td></tr></tbody></table></div></div>
    </div>`;

    setTimeout(() => {
        const d = DATA || {};
        const hist = d.history || [];
        const pd = d.current_window?.protocol_distribution || { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };
        const tp = (d.top_ports || []).slice(0, 10);

        makeChart("a-pps", { type: "line", data: { labels: hist.map(h => h.timestamp), datasets: [{ label: "PPS", data: hist.map(h => h.packet_rate), borderColor: "#8b5cf6", backgroundColor: "rgba(139,92,246,.1)", fill: true, tension: 0.3, pointRadius: 0 }] }, options: { ...BASE, scales: { x: { display: false }, y: { grid: GRID, beginAtZero: true } } } });
        makeChart("a-proto", { type: "doughnut", data: { labels: ["TCP", "UDP", "ICMP", "Other"], datasets: [{ data: [pd.TCP || 0, pd.UDP || 0, pd.ICMP || 0, pd.Other || 0], backgroundColor: ["#3b82f6", "#10b981", "#f97316", "#64748b"], borderWidth: 0 }] }, options: { ...BASE, cutout: "75%", plugins: { legend: { display: true, position: "right", labels: { color: "#94a3b8", font: { family: "'JetBrains Mono'", size: 10 } } } } } });
        makeChart("a-topports", { type: "bar", data: { labels: tp.map(p => ":" + p.port), datasets: [{ label: "Hits", data: tp.map(p => p.count), backgroundColor: "rgba(59,130,246,.6)", borderRadius: 4 }] }, options: { ...BASE, scales: { x: { grid: { display: false } }, y: { grid: GRID, beginAtZero: true } } } });

        renderIPTable("a-iptable", d.top_ips || []);
    }, 50);
}

function renderIPTable(id, ips) {
    const tb = document.getElementById(id);
    if (!tb) return;
    if (!ips || !ips.length) { tb.innerHTML = `<tr><td colspan="4" class="empty-row">No IPs tracked.</td></tr>`; return; }
    tb.innerHTML = ips.map(i => `<tr><td class="td-ip">${i.ip} <span style="font-size:0.65rem;color:var(--text-dim);margin-left:6px">${i.country || ''}</div></td><td>${fmt(i.packet_count)}</td><td>${i.unique_ports}</td><td>${riskHTML(i.risk_score)}</td></tr>`).join('');
}

// ── New API Pages ──
function renderAssets() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Network Assets Discovery</div><p style="color:var(--text-dim);margin-bottom:20px;">Automatically discovered devices communicating on the local network.</p><div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>IP Address</th><th>Type</th><th>Country</th><th>Activity</th><th>Total Data</th><th>Packets</th><th>First Seen</th><th>Last Seen</th></tr></thead><tbody id="assetsTable"><tr><td colspan="8" class="empty-row">Loading assets...</td></tr></tbody></table></div></div>`;
    fetch("/api/assets").then(r => r.json()).then(d => {
        const tb = document.getElementById("assetsTable");
        if (!d.assets || !d.assets.length) { tb.innerHTML = `<tr><td colspan="8" class="empty-row">No assets discovered yet.</td></tr>`; return; }
        tb.innerHTML = d.assets.map(a => `<tr ${a.is_new ? 'style="background:rgba(34,197,94,.05)"' : ''}><td class="td-ip">${a.ip} ${a.is_new ? '<span class="a-badge" style="background:#22c55e;color:#fff;margin-left:6px;font-size:.65rem;padding:2px 4px">NEW</span>' : ''}</td><td>${a.network_type}</td><td>${a.country}</td><td><span class="a-badge" style="background:${a.activity_level === 'High' ? 'var(--blue)' : 'var(--border)'}">${a.activity_level}</span></td><td style="font-family:var(--mono)">${a.total_bytes_human}</td><td>${fmt(a.packet_count)}</td><td style="color:var(--text-dim)">${a.first_seen.split(" ")[1]}</td><td style="color:var(--text-dim)">${a.last_seen.split(" ")[1]}</td></tr>`).join("");
    });
}

function renderDNS() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">DNS Analysis</div><p style="color:var(--text-dim);margin-bottom:20px;">Suspicious domains, DGA detection, and DNS tunneling attempts.</p><div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>Timestamp</th><th>Source IP</th><th>Domain Query</th><th>Detection Reason</th><th>DGA Score</th></tr></thead><tbody id="dnsTable"><tr><td colspan="5" class="empty-row">Loading DNS analysis...</td></tr></tbody></table></div></div>`;
    fetch("/api/dns").then(r => r.json()).then(d => {
        const tb = document.getElementById("dnsTable");
        if (!d.suspicious_domains || !d.suspicious_domains.length) { tb.innerHTML = `<tr><td colspan="5" class="empty-row">No suspicious DNS activity detected.</td></tr>`; return; }
        tb.innerHTML = d.suspicious_domains.map(s => `<tr><td style="color:var(--text-dim)">${s.timestamp.split(" ")[1]}</td><td class="td-ip">${s.src_ip}</td><td style="color:var(--accent);font-weight:600">${s.domain}</td><td>${s.reason}</td><td>${s.dga_score > 0 ? riskHTML(Math.round(s.dga_score * 100)) : '—'}</td></tr>`).join("");
    });
}

function renderBeaconing() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">C2 Beaconing Detection</div><p style="color:var(--text-dim);margin-bottom:20px;">Periodic communication patterns indicating potential Command & Control.</p><div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>Timestamp</th><th>Target IP</th><th>Src IPs</th><th>Connections</th><th>Interval</th><th>Avg Vol</th><th>Beacon Score</th></tr></thead><tbody id="beaconsTable"><tr><td colspan="7" class="empty-row">Loading beacon data...</td></tr></tbody></table></div></div>`;
    fetch("/api/beaconing").then(r => r.json()).then(d => {
        const tb = document.getElementById("beaconsTable");
        if (!d.flagged_beacons || !d.flagged_beacons.length) { tb.innerHTML = `<tr><td colspan="7" class="empty-row">No C2 beaconing patterns detected.</td></tr>`; return; }
        tb.innerHTML = d.flagged_beacons.map(b => `<tr><td style="color:var(--text-dim)">${b.timestamp.split(" ")[1]}</td><td class="td-ip">${b.dst_ip}</td><td>${b.src_ips.length}</td><td>${b.connections}</td><td>~${Math.round(b.avg_interval)}s (±${Math.round(b.jitter_ratio * 100)}%)</td><td style="font-family:var(--mono)">${b.avg_bytes} B</td><td>${riskHTML(b.beacon_score)}</td></tr>`).join("");
    });
}

function renderIncidents() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Correlated Incidents</div><div style="display:flex;justify-content:space-between;margin-bottom:20px;"><p style="color:var(--text-dim);">Alerts grouped by attacker campaign to reduce alert fatigue.</p><button onclick="window.open('/api/report?format=text', '_blank')" class="filter-btn" style="background:var(--accent);color:#fff;border:none">Generate Full Report</button></div><div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>Incident ID</th><th>Campaign Type</th><th>Source IP</th><th>Duration</th><th>Attempts</th><th>Max Risk</th><th>Actions</th></tr></thead><tbody id="incTable"><tr><td colspan="7" class="empty-row">Loading incidents...</td></tr></tbody></table></div></div>`;
    fetch("/api/incidents").then(r => r.json()).then(d => {
        const tb = document.getElementById("incTable");
        const inc = d.all_incidents || [];
        if (!inc.length) { tb.innerHTML = `<tr><td colspan="7" class="empty-row">No incidents recorded.</td></tr>`; return; }
        tb.innerHTML = inc.map((i, idx) => `<tr><td style="font-family:var(--mono);color:var(--text-dim)">${i.incident_id} ${i.active ? '<span class="a-badge" style="background:var(--red);color:#fff;margin-left:4px;font-size:.65rem">ACTIVE</span>' : ''}</td><td><strong>${i.attack_type}</strong><br><span style="font-size:.75rem;color:var(--text-dim)">${i.duration_sec > 60 ? Math.round(i.duration_sec / 60) + ' min' : i.duration_sec + ' sec'}</span></td><td class="td-ip">${i.source_ip}</td><td>${i.first_seen.split(" ")[1]} → ${i.last_seen.split(" ")[1]}</td><td>${i.count}</td><td>${riskHTML(i.max_risk)}</td><td><button onclick="window.open('/api/report?alert_index=${idx}&format=text', '_blank')" class="filter-btn">Report</button></td></tr>`).join("");
    });
}

function renderSimulation() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Attack Simulator</div><p style="color:var(--text-dim);margin-bottom:20px;">Generate synthetic attack traffic for SOC testing and demonstration.</p><div class="grid-2"><div class="card"><div class="card-header">Configure Simulation</div>
    <div style="margin:20px 0"><label style="display:block;margin-bottom:8px">Attack Type</label><select id="simType" class="search-input" style="width:100%;max-width:none;padding:10px"><option value="port_scan">Port Scan (Discovery)</option><option value="packet_flood">Packet Flood (DoS)</option><option value="brute_force">Brute Force (Credential Access)</option></select></div>
    <div style="margin:20px 0"><label style="display:block;margin-bottom:8px">Duration (seconds)</label><input type="number" id="simDur" class="search-input" value="30" min="10" max="120" style="width:100%;max-width:none;padding:10px"></div>
    <div style="display:flex;gap:10px;margin-top:30px"><button onclick="startSim()" class="btn-save" id="simBtn">START SIMULATION</button><button onclick="stopSim()" class="btn-reset" id="stopBtn" disabled>STOP</button></div>
    <div id="simMsg" style="margin-top:16px;font-family:var(--mono);font-size:.8rem"></div></div><div class="card"><div class="card-header">Simulation Status</div><div id="simLog" style="font-family:var(--mono);font-size:.8rem;color:var(--text-dim);background:var(--surface);padding:16px;border-radius:8px;min-height:200px;max-height:300px;overflow-y:auto">Fetching status...</div></div></div>`;

    const checkStatus = () => {
        if (currentPage !== 'simulation') return;
        fetch("/api/simulate/status").then(r => r.json()).then(d => {
            const bgBtn = document.getElementById("simBtn"); const stpBtn = document.getElementById("stopBtn");
            if (bgBtn) { bgBtn.disabled = d.running; bgBtn.style.opacity = d.running ? "0.5" : "1"; }
            if (stpBtn) { stpBtn.disabled = !d.running; }
            const log = document.getElementById("simLog");
            if (log) {
                if (!d.log || !d.log.length) { log.innerHTML = "No recent simulations."; }
                else { log.innerHTML = d.log.map(l => `<div style="margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid var(--border)"><span style="color:${l.status === 'running' ? 'var(--accent)' : 'var(--text)'}">[${l.started}] ${l.type} (${l.duration}s)</span> <br> <span style="font-size:.7rem;color:var(--text-dim)">Status: ${l.status.toUpperCase()}</span></div>`).join(""); }
            }
        });
        setTimeout(checkStatus, 2000);
    };
    checkStatus();
}

function renderThreat() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Threat Intelligence</div>
    <div class="card" style="text-align:center; padding: 40px;">
        <div class="gauge-area"><canvas id="threat-gauge"></canvas><div class="gauge-over"><div class="gauge-num" id="threatScoreGauge">0%</div><div class="gauge-tag" id="threatStatusGauge">Low Risk</div></div></div>
    </div>`;
    setTimeout(() => {
        const sc = DATA?.threat_level?.score || 0;
        makeChart("threat-gauge", { type: "doughnut", data: { datasets: [{ data: [sc, 100 - sc], backgroundColor: [tCol(sc), "rgba(255,255,255,0.05)"], borderWidth: 0, circumference: 180, rotation: 270 }] }, options: { ...BASE, cutout: "85%" } });
        document.getElementById("threatScoreGauge").textContent = sc + "%";
        document.getElementById("threatScoreGauge").style.color = tCol(sc);
        document.getElementById("threatStatusGauge").textContent = DATA?.threat_level?.priority || "Low";
    }, 50);
}

function renderSettings() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">System Settings</div>
    <div id="settingsLoader" style="color:var(--text-dim);font-style:italic;padding:20px;">Loading settings...</div>
    <div id="settingsContent" style="display:none;">
    <div class="grid-2">
        <div class="card">
            <div class="card-header">Detection Engine</div>
            <div class="settings-section">
                <div class="setting-row"><div class="label">Time Window<small>Sliding window duration (seconds)</small></div><input type="number" class="setting-input" id="set-time_window" min="1" max="60"></div>
                <div class="setting-row"><div class="label">Baseline Duration<small>Baseline learning period (seconds)</small></div><input type="number" class="setting-input" id="set-baseline_duration" min="10" max="600"></div>
                <div class="setting-row"><div class="label">PPS Threshold<small>Static packet-rate fallback threshold</small></div><input type="number" class="setting-input" id="set-pps_threshold" min="10" max="10000"></div>
                <div class="setting-row"><div class="label">Sigma Multiplier<small>Adaptive threshold = mean + σ × this</small></div><input type="number" class="setting-input" id="set-sigma_mult" min="0.5" max="10" step="0.1"></div>
                <div class="setting-row"><div class="label">Burst Tolerance<small>Consecutive anomaly windows before alert</small></div><input type="number" class="setting-input" id="set-burst_tolerance" min="1" max="20"></div>
                <div class="setting-row"><div class="label">Port Scan Threshold<small>Unique ports from one IP to flag scan</small></div><input type="number" class="setting-input" id="set-port_scan_threshold" min="3" max="100"></div>
                <div class="setting-row"><div class="label">Risk Alert Threshold<small>Minimum risk score to emit alert</small></div>
                    <div class="setting-slider-wrap"><input type="range" class="setting-slider" id="set-risk_alert_threshold" min="0" max="100"><span class="setting-slider-val" id="risk_slider_val">50</span></div>
                </div>
            </div>
        </div>
        <div class="card">
            <div class="card-header">Dashboard Settings</div>
            <div class="settings-section">
                <div class="setting-row"><div class="label">Polling Interval<small>Seconds between metric refreshes</small></div><input type="number" class="setting-input" id="set-polling_interval" min="1" max="30"></div>
                <div class="setting-row"><div class="label">Max Data Points<small>History points shown on charts</small></div><input type="number" class="setting-input" id="set-max_data_points" min="10" max="300"></div>
            </div>
            <div class="card-header" style="margin-top:24px;">Alert Preferences</div>
            <div class="settings-section">
                <div class="setting-row"><div class="label">Browser Notifications</div><label class="toggle-label"><input type="checkbox" id="set-browser_notifications"><span class="toggle-text">Enabled</span></label></div>
                <div class="setting-row"><div class="label">Email Alerts<small>Requires SMTP configuration</small></div><label class="toggle-label"><input type="checkbox" id="set-email_alerts"><span class="toggle-text">Enabled</span></label></div>
                <div class="setting-row"><div class="label">Telegram Alerts<small>Requires bot token + chat ID</small></div><label class="toggle-label"><input type="checkbox" id="set-telegram_alerts"><span class="toggle-text">Enabled</span></label></div>
            </div>
        </div>
    </div>
    <div class="settings-actions">
        <button class="btn-save" id="saveSettingsBtn">Save Settings</button>
        <button class="btn-reset" id="resetSettingsBtn">Reset to Defaults</button>
        <div class="save-toast" id="saveToast">✓ Settings saved</div>
    </div>
    </div>`;

    // Load current settings from backend
    fetch("/api/settings").then(r => r.json()).then(settings => {
        document.getElementById("settingsLoader").style.display = "none";
        document.getElementById("settingsContent").style.display = "block";

        const fields = [
            "time_window", "pps_threshold", "sigma_mult",
            "burst_tolerance", "port_scan_threshold", "risk_alert_threshold",
            "polling_interval", "max_data_points"
        ];
        fields.forEach(f => {
            const el = document.getElementById("set-" + f);
            if (el && settings[f] !== undefined) el.value = settings[f];
        });

        // Baseline duration comes from config.py, not settings API — default 60
        const blEl = document.getElementById("set-baseline_duration");
        if (blEl) blEl.value = settings.baseline_duration || 60;

        // Checkboxes
        const cb = (id, val) => { const el = document.getElementById(id); if (el) el.checked = !!val; };
        cb("set-browser_notifications", settings.browser_notifications !== false);
        cb("set-email_alerts", settings.email_alerts);
        cb("set-telegram_alerts", settings.telegram_alerts);

        // Slider live label
        const slider = document.getElementById("set-risk_alert_threshold");
        const sliderVal = document.getElementById("risk_slider_val");
        if (slider && sliderVal) {
            sliderVal.textContent = slider.value;
            slider.addEventListener("input", () => { sliderVal.textContent = slider.value; });
        }
    }).catch(() => {
        document.getElementById("settingsLoader").innerHTML = "Failed to load settings. Check backend connection.";
    });

    // Save handler
    document.getElementById("saveSettingsBtn")?.addEventListener("click", () => {
        const payload = {};
        const numFields = [
            "time_window", "pps_threshold", "sigma_mult",
            "burst_tolerance", "port_scan_threshold", "risk_alert_threshold",
            "polling_interval", "max_data_points", "baseline_duration"
        ];
        numFields.forEach(f => {
            const el = document.getElementById("set-" + f);
            if (el) payload[f] = parseFloat(el.value);
        });
        // Booleans
        ["browser_notifications", "email_alerts", "telegram_alerts"].forEach(f => {
            const el = document.getElementById("set-" + f);
            if (el) payload[f] = el.checked;
        });

        fetch("/api/settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        }).then(r => r.json()).then(d => {
            const toast = document.getElementById("saveToast");
            if (toast) {
                toast.classList.add("show");
                toast.textContent = d.status === "ok" ? "✓ Settings saved successfully" : "⚠ " + (d.message || "Error");
                setTimeout(() => toast.classList.remove("show"), 3000);
            }
        }).catch(() => {
            const toast = document.getElementById("saveToast");
            if (toast) { toast.textContent = "⚠ Save failed"; toast.classList.add("show"); setTimeout(() => toast.classList.remove("show"), 3000); }
        });
    });

    // Reset handler
    document.getElementById("resetSettingsBtn")?.addEventListener("click", () => {
        const defaults = { time_window: 5, pps_threshold: 100, sigma_mult: 2.0, burst_tolerance: 3, port_scan_threshold: 15, risk_alert_threshold: 50, polling_interval: 1, max_data_points: 60, baseline_duration: 60 };
        Object.entries(defaults).forEach(([k, v]) => {
            const el = document.getElementById("set-" + k);
            if (el) el.value = v;
        });
        const sliderVal = document.getElementById("risk_slider_val");
        if (sliderVal) sliderVal.textContent = "50";
        ["set-browser_notifications"].forEach(id => { const el = document.getElementById(id); if (el) el.checked = true; });
        ["set-email_alerts", "set-telegram_alerts"].forEach(id => { const el = document.getElementById(id); if (el) el.checked = false; });
    });
}

// ── Polling ──

function liveUpdate() {
    if (!DATA) return;
    const d = DATA;
    const hist = (d.history || []).slice(-MAX_PTS);
    const labels = hist.map(h => h.timestamp);

    const curLen = hist.length;
    const delta = Math.max(0, curLen - lastHistLen);
    lastHistLen = curLen;

    if (currentPage === "dashboard") {
        const s = d.summary || {};
        const tl = d.threat_level || {};
        const cw = d.current_window || {};

        const setVal = (id, val, bg) => { const e = document.getElementById(id); if (e) { e.textContent = val; if (bg) e.style.color = bg; } };
        setVal("mc-pps", cw.packet_rate || 0);
        setVal("mc-total", fmt(s.total_packets || 0));
        setVal("mc-bw", s.bandwidth || "0 B");
        setVal("mc-ips", s.unique_src_ips || 0);
        setVal("mc-alerts", s.active_alerts || 0);
        setVal("mc-threat", (tl.score || 0) + "%", tCol(tl.score || 0));

        if (delta > 0) {
            streamChart("c-pps", labels, hist.map(h => h.packet_rate), delta);
            streamChart("c-ports", labels, hist.map(h => h.unique_ports), delta);
        }
        renderAlertList("dash-alerts", (d.alerts || []).slice(0, 5));
    }

    if (currentPage === "analysis") {
        if (delta > 0) streamChart("a-pps", labels, hist.map(h => h.packet_rate), delta);
        const pd = d.current_window?.protocol_distribution || { TCP: 0, UDP: 0, ICMP: 0, Other: 0 };
        if (window.charts["a-proto"]) { window.charts["a-proto"].data.datasets[0].data = [pd.TCP || 0, pd.UDP || 0, pd.ICMP || 0, pd.Other || 0]; window.charts["a-proto"].update("none"); }
        const tp = (d.top_ports || []).slice(0, 10);
        if (window.charts["a-topports"]) { window.charts["a-topports"].data.labels = tp.map(p => ":" + p.port); window.charts["a-topports"].data.datasets[0].data = tp.map(p => p.count); window.charts["a-topports"].update("none"); }
        renderIPTable("a-iptable", d.top_ips || []);
    }

    if (currentPage === "alerts") updateAlertsFeed();

    const badge = document.getElementById("alertBadge");
    if (badge) badge.textContent = d.summary?.active_alerts ?? 0;
}

async function poll() {
    try {
        const res = await fetch("/metrics");
        if (!res.ok) throw new Error("HTTP error " + res.status);
        DATA = await res.json() || {};

        document.getElementById("livePill")?.classList.remove("offline");
        const dot = document.getElementById("statusDot");
        const txt = document.getElementById("statusText");
        if (dot) dot.className = "status-dot online";
        if (txt) txt.textContent = "Live";
        liveUpdate();
    } catch (err) {
        console.error("Poll error:", err);
        document.getElementById("livePill")?.classList.add("offline");
        const dot = document.getElementById("statusDot");
        const txt = document.getElementById("statusText");
        if (dot) dot.className = "status-dot offline";
        if (txt) txt.textContent = "Offline";
    }
}

window.startPolling = function () {
    poll();
    setInterval(poll, POLL_MS);
};

function renderAnalytics() {
    destroyCharts();
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Threat Analytics</div>
    <div class="grid-2">
        <div class="card"><div class="card-header">Attack Types</div><div class="chart-wrap"><canvas id="an-types"></canvas></div></div>
        <div class="card"><div class="card-header">Severity Distribution</div><div class="chart-wrap"><canvas id="an-sev"></canvas></div></div>
    </div>`;
    fetch("/api/analytics").then(r => r.json()).then(d => {
        const types = d.attack_types || [];
        const sev = d.severity_distribution || {};
        setTimeout(() => {
            makeChart("an-types", { type: "bar", data: { labels: types.map(t => t.type), datasets: [{ label: "Alerts", data: types.map(t => t.count), backgroundColor: "rgba(249,115,22,.8)" }] }, options: { ...BASE } });
            makeChart("an-sev", { type: "doughnut", data: { labels: Object.keys(sev), datasets: [{ data: Object.values(sev), backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#10b981"] }] }, options: { ...BASE, cutout: "70%", plugins: { legend: { display: true, position: "right" } } } });
        }, 50);
    });
}

// Global Page Registry
if (window.PAGES) {
    Object.assign(window.PAGES, {
        dashboard: renderDashboard,
        analysis: renderAnalysis,
        alerts: renderAlerts,
        incidents: renderIncidents,
        threat: renderThreat,
        dns: renderDNS,
        beaconing: renderBeaconing,
        assets: renderAssets,
        analytics: renderAnalytics,
        simulation: renderSimulation,
        settings: renderSettings
    });
}

window.startSim = function () {
    fetch("/api/simulate", { method: "POST", body: JSON.stringify({ type: document.getElementById("simType").value, duration: parseInt(document.getElementById("simDur").value) }) }).then(r => r.json()).then(d => {
        document.getElementById("simMsg").innerHTML = `<span style="color:var(--green)">✓ Started ${d.type}</span>`;
    });
}
window.stopSim = function () {
    fetch("/api/simulate/stop", { method: "POST" }).then(r => r.json()).then(d => {
        document.getElementById("simMsg").innerHTML = `<span style="color:var(--orange)">Stopped</span>`;
    });
}
