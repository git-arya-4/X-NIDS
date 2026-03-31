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

// ── Block/Unblock helpers ──
window._blockedIps = new Set();

function _refreshBlockedSet() {
    fetch("/api/block").then(r => r.json()).then(d => {
        window._blockedIps = new Set((d.blocked || []).map(b => b.ip));
    }).catch(() => { });
}
_refreshBlockedSet();

function _blockBtnHTML(ip, reason) {
    const isBlocked = window._blockedIps.has(ip);
    const eid = 'blk-' + ip.replace(/[.:]/g, '-');
    if (isBlocked) {
        return `<span id="${eid}" class="block-btn-group">
            <button class="xn-btn-blocked" disabled>🔒 BLOCKED</button>
            <button class="xn-btn-unblock" onclick="event.stopPropagation();_handleUnblock('${ip}','${eid}')">UNBLOCK</button>
        </span>`;
    }
    return `<span id="${eid}" class="block-btn-group">
        <button class="xn-btn-block" onclick="event.stopPropagation();_showBlockConfirm('${ip}','${eid}','${(reason || "").replace(/'/g, "\\'")}')">⛔ BLOCK</button>
    </span>`;
}

window._showBlockConfirm = function (ip, eid, reason) {
    const el = document.getElementById(eid);
    if (!el) return;
    el.innerHTML = `<span class="xn-block-confirm">
        Block ${ip}? This will drop all traffic.
        <button class="xn-btn-confirm" onclick="event.stopPropagation();_handleBlock('${ip}','${eid}','${reason}')">CONFIRM</button>
        <button class="xn-btn-cancel" onclick="event.stopPropagation();_cancelBlockConfirm('${ip}','${eid}','${reason}')">CANCEL</button>
    </span>`;
};

window._cancelBlockConfirm = function (ip, eid, reason) {
    const el = document.getElementById(eid);
    if (!el) return;
    el.innerHTML = `<button class="xn-btn-block" onclick="event.stopPropagation();_showBlockConfirm('${ip}','${eid}','${reason}')">⛔ BLOCK</button>`;
};

window._handleBlock = function (ip, eid, reason) {
    fetch("/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip, reason: reason || "Manual block" })
    }).then(r => r.json()).then(d => {
        if (d.status === "ok") {
            window._blockedIps.add(ip);
            const el = document.getElementById(eid);
            if (el) el.innerHTML = `<button class="xn-btn-blocked" disabled>🔒 BLOCKED</button>
                <button class="xn-btn-unblock" onclick="event.stopPropagation();_handleUnblock('${ip}','${eid}')">UNBLOCK</button>`;
            _showBlockToast(d.warning ? '⚠ ' + d.warning : '✓ ' + ip + ' blocked', d.warning ? 'warn' : 'ok');
        } else {
            _showBlockToast('Block failed — ' + (d.message || 'check server permissions'), 'err');
        }
    }).catch(() => {
        _showBlockToast('Block failed — check server permissions', 'err');
    });
};

window._handleUnblock = function (ip, eid) {
    fetch("/api/block/" + encodeURIComponent(ip), { method: "DELETE" })
        .then(r => r.json()).then(d => {
            if (d.status === "ok") {
                window._blockedIps.delete(ip);
                const el = document.getElementById(eid);
                if (el) el.innerHTML = `<button class="xn-btn-block" onclick="event.stopPropagation();_showBlockConfirm('${ip}','${eid}','')">⛔ BLOCK</button>`;
                _showBlockToast('✓ ' + ip + ' unblocked', 'ok');
                if (currentPage === 'blocked') renderBlocked();
            } else {
                _showBlockToast('Unblock failed — ' + (d.message || ''), 'err');
            }
        }).catch(() => _showBlockToast('Unblock failed', 'err'));
};

function _showBlockToast(msg, type) {
    let toast = document.getElementById('xn-block-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'xn-block-toast';
        toast.className = 'xn-toast';
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.style.borderColor = type === 'err' ? '#ef4444' : type === 'warn' ? '#f97316' : '#22c55e';
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 4000);
}

// ── PDF Report helpers ──
window._downloadPdfReport = function (url, btnEl) {
    if (btnEl) { btnEl.disabled = true; btnEl.innerHTML = '<span class="xn-spinner"></span> Generating...'; }
    fetch(url).then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.blob();
    }).then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        const cd = 'XNIDS_Report.pdf'; // fallback
        a.download = cd;
        a.click();
        URL.revokeObjectURL(a.href);
        _showBlockToast('✓ Report downloaded successfully', 'ok');
        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '📊 Generate PDF Report'; }
    }).catch(() => {
        _showBlockToast('Report generation failed', 'err');
        if (btnEl) { btnEl.disabled = false; btnEl.innerHTML = '📊 Generate PDF Report'; }
    });
};

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

function renderAlertList(containerId, alerts, showBlock) {
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
            <div style="display:flex;align-items:center;gap:8px;">
                ${a.mitre?.technique_id && a.mitre?.technique_id !== 'N/A' ? `<a href="${a.mitre?.url}" target="_blank" class="mitre-tag">${a.mitre?.technique_id}</a>` : ''}
                ${showBlock !== false ? _blockBtnHTML(a.source_ip, 'Manual block — ' + (a.attack_type || a.classification || '')) : ''}
            </div>
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
    // Fetch from live API (same store as Incidents page)
    fetch("/api/alerts").then(r => r.json()).then(d => {
        let a = d.alerts || [];
        if (filter !== "all") a = a.filter(x => (x.severity || "").toLowerCase() === filter);
        if (search) a = a.filter(x => (x.source_ip || "").includes(search) || (x.attack_type || "").toLowerCase().includes(search));
        renderAlertList("alertsFeed", a, true);
    }).catch(() => {
        // Fallback to DATA if live API fails
        let a = DATA?.alerts || [];
        if (filter !== "all") a = a.filter(x => (x.severity || "").toLowerCase() === filter);
        if (search) a = a.filter(x => (x.source_ip || "").includes(search) || (x.attack_type || "").toLowerCase().includes(search));
        renderAlertList("alertsFeed", a, true);
    });
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
        <div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>Source IP</th><th>Packets</th><th>Ports</th><th>Risk</th><th>Actions</th></tr></thead><tbody id="a-iptable"><tr><td colspan="5" class="empty-row">Checking tables...</td></tr></tbody></table></div></div>
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
    if (!ips || !ips.length) { tb.innerHTML = `<tr><td colspan="5" class="empty-row">No IPs tracked.</td></tr>`; return; }
    tb.innerHTML = ips.map(i => {
        const blocked = window._blockedIps.has(i.ip);
        return `<tr><td class="td-ip">${i.ip}${blocked ? ' <span class="xn-blocked-chip">BLOCKED</span>' : ''} <span style="font-size:0.65rem;color:var(--text-dim);margin-left:6px">${i.country || ''}</span></td><td>${fmt(i.packet_count)}</td><td>${i.unique_ports}</td><td>${riskHTML(i.risk_score)}</td><td>${_blockBtnHTML(i.ip, 'Traffic analysis — suspicious activity')}</td></tr>`;
    }).join('');
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
    main.innerHTML = `<div class="page-title">Correlated Incidents</div><div style="display:flex;justify-content:space-between;margin-bottom:20px;"><p style="color:var(--text-dim);">Alerts grouped by attacker campaign to reduce alert fatigue.</p><button id="pdfReportBtn" onclick="_downloadPdfReport('/api/report/pdf', this)" class="filter-btn" style="background:var(--accent);color:#fff;border:none">📊 Generate PDF Report</button></div><div class="card" style="padding:0"><div class="table-scroll"><table width="100%"><thead><tr><th>Incident ID</th><th>Campaign Type</th><th>Source IP</th><th>Duration</th><th>Attempts</th><th>Max Risk</th><th>Actions</th></tr></thead><tbody id="incTable"><tr><td colspan="7" class="empty-row">Loading incidents...</td></tr></tbody></table></div></div>`;
    fetch("/api/incidents").then(r => r.json()).then(d => {
        const tb = document.getElementById("incTable");
        const inc = d.all_incidents || [];
        if (!inc.length) { tb.innerHTML = `<tr><td colspan="7" class="empty-row">No incidents recorded.</td></tr>`; return; }
        tb.innerHTML = inc.map((i, idx) => `<tr><td style="font-family:var(--mono);font-size:.75rem;color:var(--text-dim)">${i.incident_id} ${i.active ? '<span class="a-badge" style="background:var(--red);color:#fff;margin-left:4px;font-size:.65rem">ACTIVE</span>' : ''}</td><td><strong>${i.attack_type}</strong><br><span style="font-size:.75rem;color:var(--text-dim)">${i.duration_sec > 60 ? Math.round(i.duration_sec / 60) + ' min' : i.duration_sec + ' sec'}</span></td><td class="td-ip">${i.source_ip}</td><td>${i.first_seen.split(" ")[1]} → ${i.last_seen.split(" ")[1]}</td><td>${i.count}</td><td>${riskHTML(i.max_risk)}</td><td style="display:flex;gap:6px;align-items:center;">${_blockBtnHTML(i.source_ip, 'Manual block — ' + (i.attack_type || ''))}<button onclick="_downloadPdfReport('/api/report/pdf?incident_id=${i.incident_id}', this)" class="filter-btn">📄 Report</button></td></tr>`).join("");
    });
}


function _updateThreatGauge(sc, priority, ago) {
    const gaugeEl = document.getElementById("threatScoreGauge");
    const statusEl = document.getElementById("threatStatusGauge");
    const lastEl = document.getElementById("threatLastAlert");
    if (gaugeEl) { gaugeEl.textContent = sc + "%"; gaugeEl.style.color = tCol(sc); }
    if (statusEl) statusEl.textContent = priority || "Low";
    if (lastEl) {
        if (ago === undefined || ago === null || ago < 0) {
            lastEl.textContent = "No critical/high alerts recorded";
        } else if (ago < 60) {
            lastEl.textContent = "Last alert: " + ago + "s ago";
        } else {
            lastEl.textContent = "Last alert: " + Math.floor(ago / 60) + " min ago";
        }
    }
    // Update gauge chart if it exists
    if (window.charts["threat-gauge"]) {
        window.charts["threat-gauge"].data.datasets[0].data = [sc, 100 - sc];
        window.charts["threat-gauge"].data.datasets[0].backgroundColor = [tCol(sc), "rgba(255,255,255,0.05)"];
        window.charts["threat-gauge"].update("none");
    }
}

function renderThreat() {
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Threat Intelligence</div>
    <div class="card" style="text-align:center; padding: 40px;">
        <div class="gauge-area"><canvas id="threat-gauge"></canvas><div class="gauge-over"><div class="gauge-num" id="threatScoreGauge">0%</div><div class="gauge-tag" id="threatStatusGauge">Low Risk</div></div></div>
        <div id="threatLastAlert" style="margin-top:16px;font-family:var(--mono);font-size:0.75rem;color:var(--text-dim);"></div>
    </div>`;
    setTimeout(() => {
        // Initial render from whatever we have in DATA
        const sc0 = DATA?.threat_level?.score || 0;
        makeChart("threat-gauge", { type: "doughnut", data: { datasets: [{ data: [sc0, 100 - sc0], backgroundColor: [tCol(sc0), "rgba(255,255,255,0.05)"], borderWidth: 0, circumference: 180, rotation: 270 }] }, options: { ...BASE, cutout: "85%" } });
        // Immediately fetch from live API
        fetch("/api/threat-score").then(r => r.json()).then(d => {
            _updateThreatGauge(d.score || 0, d.priority, d.last_alert_ago);
        }).catch(() => {
            _updateThreatGauge(sc0, DATA?.threat_level?.priority, DATA?.threat_level?.last_alert_ago);
        });
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
        </div>
    </div>
    <div class="card" style="margin-bottom: 24px;">
        <div class="card-header">Trusted IP Whitelist</div>
        <div class="settings-section">
            <div style="display:flex;gap:10px;margin-bottom:12px;">
                <input type="text" id="whitelist-input" class="setting-input" style="font-family:var(--mono);flex:1;" placeholder="e.g. 10.20.77.244 or 192.168.1.0/24">
                <button id="addWhitelistBtn" class="filter-btn active" style="padding:0 24px;border-color:var(--accent);color:var(--accent);">ADD</button>
            </div>
            <div style="color:var(--text-dim);font-size:0.75rem;margin-bottom:16px;">Whitelisted IPs will never trigger alerts regardless of traffic volume. Supports single IPs and CIDR ranges.</div>
            <div style="display:flex;gap:8px;margin-bottom:16px;" id="whitelist-quick">
                <button class="filter-btn" style="font-family:var(--mono);font-size:0.75rem;" onclick="document.getElementById('whitelist-input').value='10.0.0.0/8'">+ 10.0.0.0/8</button>
                <button class="filter-btn" style="font-family:var(--mono);font-size:0.75rem;" onclick="document.getElementById('whitelist-input').value='192.168.0.0/16'">+ 192.168.0.0/16</button>
                <button class="filter-btn" style="font-family:var(--mono);font-size:0.75rem;" onclick="document.getElementById('whitelist-input').value='127.0.0.1'">+ 127.0.0.1</button>
            </div>
            <div id="whitelist-chips" style="display:flex;flex-wrap:wrap;gap:8px;"></div>
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

        window.currentWhitelist = settings.whitelist || [];
        window.renderWhitelist = () => {
            const container = document.getElementById("whitelist-chips");
            if (container) {
                container.innerHTML = window.currentWhitelist.map((ip, i) => `
                    <div style="display:inline-flex;align-items:center;padding:4px 8px;border:1px solid rgba(59,130,246,0.3);border-radius:4px;font-family:var(--mono);font-size:0.75rem;background:rgba(59,130,246,0.05);">
                        ${ip}
                        <button onclick="window.removeWhitelist(${i})" style="background:none;border:none;color:var(--text-dim);margin-left:8px;cursor:pointer;">✕</button>
                    </div>
                `).join('');
            }
        };
        window.removeWhitelist = (idx) => { window.currentWhitelist.splice(idx, 1); window.renderWhitelist(); };
        window.renderWhitelist();

        document.getElementById("addWhitelistBtn")?.addEventListener("click", () => {
            const val = document.getElementById("whitelist-input")?.value.trim();
            if (val && !window.currentWhitelist.includes(val)) {
                window.currentWhitelist.push(val);
                window.renderWhitelist();
                document.getElementById("whitelist-input").value = "";
            }
        });

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
        payload["whitelist"] = window.currentWhitelist || [];

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
        const defaults = { time_window: 5, pps_threshold: 500, sigma_mult: 2.5, burst_tolerance: 6, port_scan_threshold: 15, risk_alert_threshold: 70, polling_interval: 1, max_data_points: 60, baseline_duration: 300 };
        Object.entries(defaults).forEach(([k, v]) => {
            const el = document.getElementById("set-" + k);
            if (el) el.value = v;
        });
        const sliderVal = document.getElementById("risk_slider_val");
        if (sliderVal) sliderVal.textContent = "70";

        window.currentWhitelist = [];
        if (window.renderWhitelist) window.renderWhitelist();
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

    // Live-update threat score page from dedicated endpoint
    if (currentPage === "threat") {
        fetch("/api/threat-score").then(r => r.json()).then(d => {
            _updateThreatGauge(d.score || 0, d.priority, d.last_alert_ago);
        }).catch(() => { });
    }

    const badge = document.getElementById("alertBadge");
    if (badge) badge.textContent = d.summary?.active_alerts ?? 0;
}

async function poll() {
    try {
        const res = await fetch("/metrics");
        if (!res.ok) throw new Error("HTTP error " + res.status);
        DATA = await res.json() || {};

        const statusEl = document.getElementById("livePill");
        const labelEl = document.getElementById("liveLabel");
        if (statusEl) {
            statusEl.classList.remove("status--offline", "live-pill", "offline");
            statusEl.classList.add("status--live");
        }
        if (labelEl) labelEl.textContent = "LIVE";

        liveUpdate();
    } catch (err) {
        console.error("Poll error:", err);
        const statusEl = document.getElementById("livePill");
        const labelEl = document.getElementById("liveLabel");
        if (statusEl) {
            statusEl.classList.remove("status--live", "live-pill", "offline");
            statusEl.classList.add("status--offline");
        }
        if (labelEl) labelEl.textContent = "OFFLINE";
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
        <div class="card" style="min-height: 300px; display: flex; flex-direction: column;">
            <div class="card-header">Attack Types</div>
            <div class="chart-wrap" id="cw-types" style="flex: 1;"><canvas id="an-types"></canvas></div>
            <div id="es-types" style="display: none; flex: 1; flex-direction: column; align-items: center; justify-content: center; font-family: var(--font-ui); color: var(--color-text-muted); text-align: center;">
                <div style="font-size: 2rem; margin-bottom: 12px;">🛡</div>
                <div style="font-weight: 600; font-size: 1rem; margin-bottom: 6px;">No attacks detected in this period</div>
                <div style="font-size: 0.85rem; max-width: 80%;">Attack type distribution will appear<br>here when threats are detected.</div>
            </div>
        </div>
        <div class="card" style="min-height: 300px; display: flex; flex-direction: column;">
            <div class="card-header">Severity Distribution</div>
            <div class="chart-wrap" id="cw-sev" style="flex: 1;"><canvas id="an-sev"></canvas></div>
            <div id="es-sev" style="display: none; flex: 1; flex-direction: column; align-items: center; justify-content: center; font-family: var(--font-ui); color: var(--color-text-muted); text-align: center;">
                <div style="font-size: 2rem; margin-bottom: 12px;">✅</div>
                <div style="font-weight: 600; font-size: 1rem; margin-bottom: 6px;">No threats recorded</div>
                <div style="font-size: 0.85rem; max-width: 80%;">Severity breakdown will appear<br>here when alerts are generated.</div>
            </div>
        </div>
    </div>`;
    fetch("/api/analytics").then(r => r.json()).then(d => {
        const types = d.attack_types || [];
        const sev = d.severity_distribution || {};
        const sevKeys = Object.keys(sev);

        const cwTypes = document.getElementById("cw-types");
        const esTypes = document.getElementById("es-types");
        if (!types || types.length === 0) {
            cwTypes.style.display = 'none';
            esTypes.style.display = 'flex';
        } else {
            cwTypes.style.display = 'block';
            esTypes.style.display = 'none';
        }

        const cwSev = document.getElementById("cw-sev");
        const esSev = document.getElementById("es-sev");
        if (!sevKeys || sevKeys.length === 0) {
            cwSev.style.display = 'none';
            esSev.style.display = 'flex';
        } else {
            cwSev.style.display = 'block';
            esSev.style.display = 'none';
        }

        setTimeout(() => {
            if (types && types.length > 0) {
                makeChart("an-types", { type: "bar", data: { labels: types.map(t => t.type), datasets: [{ label: "Alerts", data: types.map(t => t.count), backgroundColor: "rgba(249,115,22,.8)" }] }, options: { ...BASE } });
            }
            if (sevKeys && sevKeys.length > 0) {
                makeChart("an-sev", { type: "doughnut", data: { labels: sevKeys, datasets: [{ data: Object.values(sev), backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#10b981"] }] }, options: { ...BASE, cutout: "70%", plugins: { legend: { display: true, position: "right" } } } });
            }
        }, 50);
    });
}

// ── Geo Threat Map ──
function _addGeoMarker(map, m) {
    const color = m.risk > 60 ? "#FF2D55" : m.risk > 30 ? "#FF6B00" : "#00FF88";
    const radius = m.risk > 60 ? 10 : m.risk > 30 ? 7 : 5;
    let marker;
    if (m.risk > 60) {
        const size = radius * 2;
        marker = L.marker([m.lat, m.lon], {
            icon: L.divIcon({
                className: "",
                html: `<div class="geo-pulse-dot"></div>`,
                iconSize: [size, size],
                iconAnchor: [size / 2, size / 2],
            })
        }).addTo(map);
    } else {
        marker = L.circleMarker([m.lat, m.lon], {
            radius: radius, color: color, fillColor: color, fillOpacity: 0.6, weight: 1.5,
        }).addTo(map);
    }
    marker.bindPopup(`<div style="font-family:var(--mono);font-size:12px;line-height:1.8;">
        <strong>${m.ip}</strong><br>
        ${m.country}${m.city ? " · " + m.city : ""}<br>
        Packets: ${m.packets}<br>
        Risk: <span style="color:${color};font-weight:700;">${m.risk}</span><br>
        ${m.first_seen ? "Seen: " + m.first_seen : ""}
    </div>`);
}

function renderGeomap() {
    destroyCharts();
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Geo Threat Map</div>
    <div class="card" style="padding:0;position:relative;overflow:hidden;">
        <div id="geomap-stats" style="position:absolute;top:16px;right:16px;z-index:600;display:flex;gap:12px;">
            <div class="geo-stat-pill"><span style="color:var(--text-dim)">COUNTRIES</span> <strong id="geo-countries">0</strong></div>
            <div class="geo-stat-pill"><span style="color:var(--text-dim)">HIGH RISK</span> <strong id="geo-high" style="color:var(--red)">0</strong></div>
        </div>
        <div id="geomap-resolve-indicator" style="display:none;position:absolute;bottom:16px;left:16px;z-index:600;
            background:rgba(10,10,10,.85);border:1px solid rgba(59,130,246,.4);border-radius:8px;padding:8px 16px;
            font-family:var(--mono);font-size:0.78rem;color:#94a3b8;backdrop-filter:blur(6px);display:none;align-items:center;gap:8px;">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#3b82f6;animation:geo-blink 1s infinite;"></span>
            <span id="geomap-resolve-text">Resolving IPs...</span>
        </div>
        <div id="geomap-container" style="height:calc(100vh - 160px);min-height:550px;width:100%;background:#0a0a0a;"></div>
        <div id="geomap-empty-overlay" class="geomap-empty-overlay" style="display:none;">
            <div class="geomap-empty-card">
                <div style="font-size:2.4rem;margin-bottom:12px;">🌐</div>
                <div style="font-weight:700;font-size:1.05rem;margin-bottom:8px;">No External Threats Detected</div>
                <div style="color:var(--text-dim);font-size:0.82rem;line-height:1.6;max-width:340px;">All current traffic is from internal/private IP ranges. External threat markers will appear here when traffic from public IPs is detected.</div>
            </div>
        </div>
    </div>
    <style>@keyframes geo-blink{0%,100%{opacity:.3}50%{opacity:1}}</style>`;

    setTimeout(() => {
        if (!window.L) { document.getElementById("geomap-container").innerHTML = '<p class="empty-msg">Leaflet.js not loaded.</p>'; return; }
        if (window._geomapInstance) { window._geomapInstance.remove(); }
        const map = L.map("geomap-container", {
            zoomControl: true,
            scrollWheelZoom: true,
            worldCopyJump: false,
            maxBoundsViscosity: 1.0,
            maxBounds: [[-90, -180], [90, 180]],
            minZoom: 2,
            maxZoom: 10,
        }).setView([20, 0], 2);
        window._geomapInstance = map;
        L.tileLayer("https://cartodb-basemaps-a.global.ssl.fastly.net/dark_all/{z}/{x}/{y}.png", {
            attribution: '&copy; CARTO', maxZoom: 18, noWrap: true
        }).addTo(map);
        setTimeout(() => { map.invalidateSize(); }, 200);

        // Running totals for stats
        let allCountries = new Set();
        let totalHighRisk = 0;

        function updateStats() {
            const s = document.getElementById("geo-countries"); if (s) s.textContent = allCountries.size;
            const h = document.getElementById("geo-high"); if (h) h.textContent = totalHighRisk;
        }

        function plotMarkers(markers) {
            markers.forEach(m => {
                _addGeoMarker(map, m);
                if (m.country) allCountries.add(m.country);
                if (m.risk > 60) totalHighRisk++;
            });
            updateStats();
        }

        // Step 1: Fetch cached markers + pending IPs
        fetch("/api/geo/threats").then(r => r.json()).then(d => {
            const emptyOverlay = document.getElementById("geomap-empty-overlay");
            const cachedMarkers = d.markers || [];
            const pendingIps = d.pending_ips || [];
            const pendingIpData = d.pending_ip_data || {};
            const totalIps = d.total_ips || 0;

            // Plot cached markers immediately
            plotMarkers(cachedMarkers);

            if (cachedMarkers.length === 0 && pendingIps.length === 0) {
                if (emptyOverlay) emptyOverlay.style.display = "flex";
                return;
            }
            if (emptyOverlay) emptyOverlay.style.display = "none";

            // Step 2: If there are pending IPs, show indicator and batch-resolve
            if (pendingIps.length > 0) {
                const indicator = document.getElementById("geomap-resolve-indicator");
                const indicatorText = document.getElementById("geomap-resolve-text");
                if (indicator) indicator.style.display = "flex";
                if (indicatorText) indicatorText.textContent = `Resolving ${pendingIps.length} IP${pendingIps.length > 1 ? 's' : ''}...`;

                fetch("/api/geo/resolve", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ ips: pendingIps, ip_data: pendingIpData })
                }).then(r => r.json()).then(rd => {
                    const newMarkers = rd.markers || [];
                    plotMarkers(newMarkers);

                    // If still zero markers total, show empty overlay
                    if (cachedMarkers.length === 0 && newMarkers.length === 0) {
                        if (emptyOverlay) emptyOverlay.style.display = "flex";
                    }

                    // Hide indicator
                    if (indicator) indicator.style.display = "none";
                }).catch(() => {
                    if (indicator) indicator.style.display = "none";
                });
            }
        }).catch(() => { });
    }, 100);
}

// ── MITRE ATT&CK Matrix ──
function renderAttackMatrix() {
    destroyCharts();
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">MITRE ATT&CK Matrix</div>
    <p style="color:var(--text-dim);margin-bottom:20px;">Detected alerts mapped to MITRE ATT&CK tactics and techniques.</p>
    <div id="attack-grid" class="attack-grid"></div>
    <div id="attack-detail-overlay" class="attack-detail-overlay hidden"></div>`;

    fetch("/api/attack/mapping").then(r => r.json()).then(d => {
        const grid = document.getElementById("attack-grid");
        const tactics = d.tactics || [];
        const techniques = d.techniques || [];
        const techByTactic = {};
        tactics.forEach(t => { techByTactic[t.id] = []; });
        techniques.forEach(t => {
            if (techByTactic[t.tactic_id]) techByTactic[t.tactic_id].push(t);
        });

        grid.innerHTML = tactics.map(tactic => {
            const techs = techByTactic[tactic.id] || [];
            const allTechsForTactic = techniques.filter(t => t.tactic_id === tactic.id);
            // Also show known techniques with 0 alerts
            const knownForTactic = Object.values(window._MITRE_KNOWN || {}).filter(k => k.tactic_id === tactic.id);

            return `<div class="attack-tactic-col">
                <div class="attack-tactic-header">${tactic.name}</div>
                ${techs.length > 0 ? techs.map(t => `
                    <div class="attack-tech-card ${t.alert_count > 0 ? 'active' : 'dimmed'}" onclick="showAttackDetail('${t.technique_id}')">
                        <div class="attack-tech-id">${t.technique_id}</div>
                        <div class="attack-tech-name">${t.technique_name}</div>
                        ${t.alert_count > 0 ? `<span class="attack-tech-badge">${t.alert_count}</span>` : ''}
                    </div>
                `).join('') : `<div class="attack-tech-card dimmed"><div class="attack-tech-name" style="opacity:0.4">No techniques detected</div></div>`}
            </div>`;
        }).join('');

        window._attackTechniques = {};
        techniques.forEach(t => { window._attackTechniques[t.technique_id] = t; });
    }).catch(() => {
        document.getElementById("attack-grid").innerHTML = '<p class="empty-msg">Failed to load ATT&CK mapping.</p>';
    });
}

window.showAttackDetail = function (techId) {
    const t = window._attackTechniques?.[techId];
    if (!t) return;
    const overlay = document.getElementById("attack-detail-overlay");
    if (!overlay) return;
    overlay.classList.remove("hidden");
    overlay.innerHTML = `<div class="attack-detail-panel">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
            <div><span class="attack-tech-id" style="font-size:1rem;">${t.technique_id}</span></div>
            <button onclick="document.getElementById('attack-detail-overlay').classList.add('hidden')" style="background:none;border:none;color:var(--text-dim);font-size:20px;cursor:pointer;">✕</button>
        </div>
        <h3 style="margin-bottom:12px;font-size:1.1rem;">${t.technique_name}</h3>
        <p style="color:var(--text-dim);margin-bottom:16px;line-height:1.6;">${t.description}</p>
        <div class="card-header" style="margin-top:0;">Alerts Triggered</div>
        <div style="margin-bottom:16px;">
            ${t.alerts && t.alerts.length > 0 ? t.alerts.map(a => `<div style="padding:6px 0;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:0.78rem;">
                <span class="td-ip">${a.source_ip}</span> · ${a.timestamp}
            </div>`).join('') : '<p class="empty-msg">No alerts triggered for this technique.</p>'}
        </div>
        <div class="card-header" style="margin-top:12px;">Recommended Action</div>
        <p style="color:var(--green);font-size:0.85rem;line-height:1.5;">${t.action}</p>
    </div>`;
    overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.classList.add("hidden"); });
};

// ── IP Reputation Lookup (standalone section for analysis page) ──
const _origRenderAnalysis = typeof renderAnalysis === 'function' ? renderAnalysis : null;
function renderAnalysisWithReputation() {
    if (_origRenderAnalysis) _origRenderAnalysis();
    setTimeout(() => {
        const main = document.getElementById("main");
        if (!main || currentPage !== "analysis") return;
        const repPanel = document.createElement("div");
        repPanel.className = "card";
        repPanel.style.marginTop = "24px";
        repPanel.innerHTML = `<div class="card-header">IP Reputation Lookup</div>
            <div style="display:flex;gap:10px;margin-bottom:16px;">
                <input type="text" id="rep-ip-input" class="setting-input" style="font-family:var(--mono);flex:1;" placeholder="Enter IP address (e.g. 1.2.3.4)">
                <button id="rep-check-btn" class="filter-btn active" style="padding:0 24px;">CHECK</button>
            </div>
            <div id="rep-result" style="display:none;" class="settings-section"></div>
            <div id="rep-unconfigured" style="display:none;color:var(--text-dim);font-size:0.78rem;font-style:italic;">Add <span style="font-family:var(--mono)">ABUSEIPDB_API_KEY</span> to your .env file for reputation lookups.</div>`;
        main.appendChild(repPanel);

        document.getElementById("rep-check-btn")?.addEventListener("click", () => {
            const ip = document.getElementById("rep-ip-input")?.value.trim();
            if (!ip) return;
            const resEl = document.getElementById("rep-result");
            const uncEl = document.getElementById("rep-unconfigured");
            resEl.style.display = "none";
            uncEl.style.display = "none";
            resEl.innerHTML = '<p style="color:var(--text-dim)">Checking...</p>';
            resEl.style.display = "block";

            fetch("/api/reputation/" + encodeURIComponent(ip)).then(r => r.json()).then(d => {
                if (d.status === "unconfigured") {
                    resEl.style.display = "none";
                    uncEl.style.display = "block";
                    return;
                }
                if (d.status === "private") {
                    resEl.innerHTML = '<p style="color:var(--text-dim)">Private IP — no external reputation data.</p>';
                    return;
                }
                if (d.status === "error") {
                    resEl.innerHTML = `<p style="color:var(--red)">${d.message}</p>`;
                    return;
                }
                const labelColor = d.label === "MALICIOUS" ? "var(--red)" : d.label === "SUSPICIOUS" ? "var(--orange)" : "var(--green)";
                resEl.innerHTML = `<div class="ad-grid" style="margin-bottom:0;">
                    <div class="ad-kv"><span>Verdict</span><b style="color:${labelColor}">${d.label === "MALICIOUS" ? "☠ " : ""}${d.label}</b></div>
                    <div class="ad-kv"><span>Abuse Score</span><b>${d.abuse_confidence}%</b></div>
                    <div class="ad-kv"><span>Reports</span><b>${d.total_reports}</b></div>
                    <div class="ad-kv"><span>Last Report</span><b style="font-size:.7rem">${d.last_reported || 'Never'}</b></div>
                    <div class="ad-kv"><span>ISP</span><b style="font-size:.65rem;word-break:break-all">${d.isp || 'N/A'}</b></div>
                    <div class="ad-kv"><span>Usage</span><b>${d.usage_type || 'N/A'}</b></div>
                    <div class="ad-kv"><span>Country</span><b>${d.country || 'N/A'}</b></div>
                    <div class="ad-kv"><span>Tor Exit</span><b>${d.is_tor ? 'Yes' : 'No'}</b></div>
                </div>`;
            }).catch(() => {
                resEl.innerHTML = '<p style="color:var(--red)">Request failed.</p>';
            });
        });
    }, 200);
}

// ── Alert Suppression Rules (added to settings) ──
const _origRenderSettings = typeof renderSettings === 'function' ? renderSettings : null;
function renderSettingsWithSuppression() {
    if (_origRenderSettings) _origRenderSettings();
    setTimeout(() => {
        const main = document.getElementById("main");
        if (!main || currentPage !== "settings") return;
        const content = document.getElementById("settingsContent");
        if (!content) return;
        const actionsDiv = content.querySelector(".settings-actions");
        if (!actionsDiv) return;

        const supPanel = document.createElement("div");
        supPanel.className = "card";
        supPanel.style.marginBottom = "24px";
        supPanel.innerHTML = `<div class="card-header">Suppression Rules</div>
            <div class="settings-section">
                <div style="display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">
                    <select id="sup-type" class="setting-input" style="width:auto;">
                        <option value="ip">Suppress alerts from IP Address</option>
                        <option value="alert_type">Suppress Alert Type</option>
                    </select>
                    <input type="text" id="sup-target" class="setting-input" style="font-family:var(--mono);flex:1;min-width:160px;" placeholder="IP address or alert classification">
                    <select id="sup-duration" class="setting-input" style="width:auto;">
                        <option value="30">30 min</option>
                        <option value="60">1 hour</option>
                        <option value="360">6 hours</option>
                        <option value="1440">24 hours</option>
                        <option value="0">Until manually cleared</option>
                    </select>
                    <button id="addSupBtn" class="filter-btn active" style="padding:5px 20px;">ADD RULE</button>
                </div>
                <div style="color:var(--text-dim);font-size:0.75rem;margin-bottom:16px;">Suppression rules temporarily silence alerts without modifying detection thresholds or the whitelist.</div>
                <div class="table-scroll"><table width="100%"><thead><tr>
                    <th>Rule</th><th>Target</th><th>Expires</th><th>Suppressed</th><th></th>
                </tr></thead><tbody id="sup-table-body"><tr><td colspan="5" class="empty-row">Loading...</td></tr></tbody></table></div>
            </div>`;
        content.insertBefore(supPanel, actionsDiv);

        function loadSupRules() {
            fetch("/api/suppress").then(r => r.json()).then(d => {
                const tb = document.getElementById("sup-table-body");
                if (!tb) return;
                const rules = d.rules || [];
                if (!rules.length) { tb.innerHTML = '<tr><td colspan="5" class="empty-row">No active suppression rules.</td></tr>'; return; }
                tb.innerHTML = rules.map(r => {
                    let expStr = "∞ Manual";
                    if (r.expires > 0) {
                        const rem = Math.max(0, Math.round((r.expires - Date.now() / 1000) / 60));
                        expStr = rem > 60 ? Math.round(rem / 60) + "h " + (rem % 60) + "m" : rem + " min";
                        if (rem <= 0) expStr = "Expired";
                    }
                    return `<tr>
                        <td style="font-family:var(--mono);font-size:.75rem;color:var(--text-dim)">${r.id}</td>
                        <td style="font-family:var(--mono);font-weight:600">${r.target}<br><span style="font-size:.65rem;color:var(--text-dim)">${r.type}</span></td>
                        <td>${expStr}</td>
                        <td style="font-family:var(--mono)">${r.suppressed_count || 0}</td>
                        <td><button onclick="deleteSupRule('${r.id}')" style="background:none;border:1px solid var(--red);color:var(--red);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:.75rem;">✕</button></td>
                    </tr>`;
                }).join('');
            }).catch(() => { });
        }
        loadSupRules();

        window.deleteSupRule = function (id) {
            fetch("/api/suppress/" + id, { method: "DELETE" }).then(() => loadSupRules()).catch(() => { });
        };

        document.getElementById("addSupBtn")?.addEventListener("click", () => {
            const type = document.getElementById("sup-type")?.value || "ip";
            const target = document.getElementById("sup-target")?.value.trim();
            const duration = parseInt(document.getElementById("sup-duration")?.value || "0");
            if (!target) return;
            fetch("/api/suppress", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ type, target, duration_minutes: duration })
            }).then(() => {
                document.getElementById("sup-target").value = "";
                loadSupRules();
            }).catch(() => { });
        });
    }, 300);
}

// ── Blocked IPs Page ──
function renderBlocked() {
    destroyCharts();
    const main = document.getElementById("main");
    main.innerHTML = `<div class="page-title">Blocked IPs</div>
    <p style="color:var(--text-dim);margin-bottom:20px;">IP addresses blocked from accessing the network. Blocks are enforced at OS firewall level when available.</p>
    <div class="card" style="padding:0"><div class="table-scroll"><table width="100%">
        <thead><tr><th>IP Address</th><th>Blocked At</th><th>Reason</th><th>Method</th><th>Packets Dropped</th><th>Actions</th></tr></thead>
        <tbody id="blockedTable"><tr><td colspan="6" class="empty-row">Loading...</td></tr></tbody>
    </table></div></div>`;

    fetch("/api/block").then(r => r.json()).then(d => {
        const tb = document.getElementById("blockedTable");
        const blocked = d.blocked || [];
        if (!blocked.length) { tb.innerHTML = '<tr><td colspan="6" class="empty-row">No blocked IPs. Use the ⛔ BLOCK button on Alerts, Incidents, or Traffic Analysis pages to block suspicious IPs.</td></tr>'; return; }
        tb.innerHTML = blocked.map(b => {
            const eid = 'ub-' + b.ip.replace(/[.:]/g, '-');
            const methodLabel = b.os_blocked ? `<span style="color:var(--green)">${b.method}</span>` : `<span style="color:var(--orange)">software only</span>`;
            return `<tr>
                <td style="font-family:var(--mono);font-weight:600">${b.ip}</td>
                <td style="color:var(--text-dim);font-size:.8rem">${b.blocked_at || 'N/A'}</td>
                <td style="font-size:.8rem">${b.reason || 'Manual block'}</td>
                <td>${methodLabel}</td>
                <td style="font-family:var(--mono)">${b.packets_dropped || 0}</td>
                <td><button id="${eid}" onclick="_handleUnblock('${b.ip}','${eid}')" class="xn-btn-unblock">UNBLOCK</button></td>
            </tr>`;
        }).join('');

        // Show software-only warning if any blocks are software-only
        if (blocked.some(b => !b.os_blocked)) {
            const warn = document.createElement('div');
            warn.className = 'xn-sw-warning';
            warn.innerHTML = '⚠ Software block only — OS firewall unavailable. Run as root for full enforcement.';
            main.querySelector('.card').before(warn);
        }
    }).catch(() => {
        document.getElementById('blockedTable').innerHTML = '<tr><td colspan="6" class="empty-row">Failed to load blocked IPs.</td></tr>';
    });
}

// Global Page Registry
if (window.PAGES) {
    Object.assign(window.PAGES, {
        dashboard: renderDashboard,
        analysis: renderAnalysisWithReputation,
        alerts: renderAlerts,
        incidents: renderIncidents,
        threat: renderThreat,
        dns: renderDNS,
        beaconing: renderBeaconing,
        assets: renderAssets,
        analytics: renderAnalytics,
        settings: renderSettingsWithSuppression,
        geomap: renderGeomap,
        attack: renderAttackMatrix,
        blocked: renderBlocked,
    });
}

