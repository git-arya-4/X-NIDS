/**
 * X-NIDS SOC — Main JS
 * Handles global UI, routing, theme toggle, and initialization.
 */

// Global State
window.currentPage = "dashboard";
window.lastHistLen = 0;
window.pollInterval = null;
window.clockInterval = null;

// Common Utilities
function tCol(s) { if (s > 75) return "#ef4444"; if (s > 50) return "#f97316"; if (s > 25) return "#eab308"; return "#22c55e"; }
function fmt(n) { if (n >= 1e6) return (n / 1e6).toFixed(1) + "M"; if (n >= 1e3) return (n / 1e3).toFixed(1) + "K"; return n ? n.toLocaleString() : "0"; }
function riskHTML(sc) { return `<span class="risk-pill" style="background:${tCol(sc)};color:${sc >= 60 ? '#fff' : '#111827'}">${sc}</span>`; }
function sevClass(s) { return s ? s.toLowerCase() : 'low'; }

// ── Routing ──
window.PAGES = {
    // These will be populated by other scripts
};

function navigate(page) {
    // Tear down netmap fully (rAF loop + interval + resize listener)
    if (page !== "netmap") {
        if (window._netmapCleanup) window._netmapCleanup();
        if (window.netmapInterval) { clearInterval(window.netmapInterval); window.netmapInterval = null; }
    }

    currentPage = page;
    document.querySelectorAll(".nav-link").forEach(l => l.classList.toggle("active", l.dataset.page === page));

    const crumbs = {
        dashboard: "Dashboard", analysis: "Traffic Analysis", alerts: "Alerts", incidents: "Correlated Incidents",
        threat: "Threat Score", dns: "DNS Analysis", beaconing: "C2 Beaconing", assets: "Network Assets",
        analytics: "Analytics", netmap: "Network Map", simulation: "Attack Simulator", settings: "Settings"
    };

    const crumbEl = document.getElementById("pageCrumb");
    if (crumbEl) crumbEl.textContent = crumbs[page] || page;

    if (PAGES[page]) {
        PAGES[page]();
    } else {
        console.warn(`Page function for ${page} not found.`);
    }
}

// ── Theme Toggle ──
function initTheme() {
    const themeBtn = document.getElementById("themeToggle");
    const root = document.documentElement;

    const applyTheme = (theme) => {
        if (theme === "light") {
            root.classList.add("light");
            root.classList.remove("dark");
        } else {
            root.classList.add("dark");
            root.classList.remove("light");
        }

        // Update Chart defaults based on theme
        if (window.Chart) {
            const isLight = theme === "light";
            Chart.defaults.color = isLight ? "#475569" : "#64748b";
            Chart.defaults.borderColor = isLight ? "#e2e8f0" : "#1c2333";
            if (window.charts) {
                Object.values(window.charts).forEach(c => c.update("none"));
            }
        }
    };

    const savedTheme = localStorage.getItem("xnids_theme") || "dark";
    applyTheme(savedTheme);

    if (themeBtn) {
        themeBtn.addEventListener("click", () => {
            const isLight = root.classList.contains("light");
            const newTheme = isLight ? "dark" : "light";
            localStorage.setItem("xnids_theme", newTheme);
            applyTheme(newTheme);
        });
    }
}

// ── Clock ──
function updateClock() {
    const el = document.getElementById("clock");
    if (el) {
        const now = new Date();
        const str = now.toLocaleTimeString("en-US", { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' | ' + now.toLocaleDateString("en-US", { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase();
        el.textContent = str;
    }
}

// ── Global Initialization ──
function globalInit() {
    console.log("X-NIDS Initialization...");

    initTheme();

    // Set up navigation links
    document.querySelectorAll(".nav-link").forEach(link => {
        link.addEventListener("click", e => {
            e.preventDefault();
            navigate(link.dataset.page);
        });
    });

    // Clock
    updateClock();
    clockInterval = setInterval(updateClock, 1000);

    // Initial navigation
    navigate("dashboard");

    // IP Click Handler (Investigation Modal)
    document.addEventListener("click", async (e) => {
        const td = e.target.closest(".td-ip");
        if (td && !td.closest('.a-meta')) {
            const ip = td.textContent.trim().replace("NEW", "").trim();
            if (ip && ip !== "None") {
                let overlay = document.getElementById("ip-modal-overlay"); if (overlay) overlay.remove();
                overlay = document.createElement("div"); overlay.id = "ip-modal-overlay"; overlay.className = "modal-overlay";
                overlay.innerHTML = `<div class="modal-panel" id="ip-modal"><p>Loading ${ip}...</p></div>`; document.body.appendChild(overlay);
                overlay.addEventListener("click", (ev) => { if (ev.target === overlay) overlay.remove(); });

                let data; try { const res = await fetch("/api/ip/" + encodeURIComponent(ip)); data = await res.json(); } catch { data = { ip, error: "Failed" }; }
                const dp = data.device_profile, alerts = data.alerts || [], tl = data.timeline || [];
                const modal = document.getElementById("ip-modal");
                if (modal) modal.innerHTML = `
                <div class="modal-header"><h2>${data.ip}</h2><button class="modal-close" onclick="document.getElementById('ip-modal-overlay').remove()">✕</button></div>
                <div class="ad-grid" style="margin-bottom:16px"><div class="ad-kv"><span>Type</span><b>${data.network_type || 'N/A'}</b></div><div class="ad-kv"><span>Country</span><b>${data.country || 'N/A'}</b></div><div class="ad-kv"><span>ISP</span><b style="font-size:.65rem;word-break:break-all">${data.isp || 'N/A'}</b></div><div class="ad-kv"><span>Packets</span><b>${fmt(data.packet_count || 0)}</b></div><div class="ad-kv"><span>Ports</span><b>${data.unique_ports || 0}</b></div><div class="ad-kv"><span>Alerts</span><b style="color:${alerts.length ? 'var(--red)' : 'var(--green)'}">${alerts.length}</b></div></div>
                ${dp ? `<div class="ad-section"><h4>Device Behaviour Profile</h4><div class="ad-grid"><div class="ad-kv"><span>Avg PPS</span><b>${dp.avg_pps}</b></div><div class="ad-kv"><span>Windows</span><b>${dp.windows}</b></div><div class="ad-kv"><span>First Seen</span><b>${dp.first_seen}</b></div><div class="ad-kv"><span>Known Ports</span><b>${dp.known_ports?.length || 0}</b></div></div></div>` : ''}
                ${tl.length ? `<div class="ad-section"><h4>Attack Timeline</h4><div class="ad-timeline">${tl.map(t => `<div class="tl-item"><span class="tl-time">${t.timestamp}</span><span class="tl-event">${t.event} (${t.risk_score} risk)</span><span class="tl-detail">${t.details || ''}</span></div>`).join('')}</div></div>` : ''}`;
            }
        }
    });

    // Start main metric polling if not already started
    if (window.startPolling) {
        window.startPolling();
    }
}

document.addEventListener("DOMContentLoaded", globalInit);
