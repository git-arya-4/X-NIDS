/**
 * X-NIDS SOC — Network Topology Map (Optimized)
 *
 * Performance optimizations:
 *  - requestAnimationFrame render loop (no setInterval draw)
 *  - Layout computed once, only recomputed when node count changes
 *  - Shadows replaced with pre-rendered radial-gradient circles (GPU-friendly)
 *  - Font set once per category, not per node
 *  - Offscreen bitmap cache for the static center hub
 *  - Node dragging with pointer events
 *  - Data polling decoupled from rendering
 *  - Resize handler throttled via rAF
 */

window.netmapInterval = null;
window._netmapCleanup = null;        // cleanup hook so navigate() can tear down

function renderNetmap() {
    const main = document.getElementById("main");
    if (!main) return;

    main.innerHTML = `
    <div class="page-title">Network Topology Map</div>
    <div class="card" style="position:relative;height:600px;overflow:hidden;padding:0;background:var(--bg);border:1px solid var(--border);" id="map-container">
        <canvas id="netCanvas" style="position:absolute;inset:0;"></canvas>
        <div class="netmap-legend" style="background:var(--surface);border:1px solid var(--border);color:var(--text-dim)">
            <span><span class="nl-dot" style="background:#3b82f6"></span> Internal Host</span>
            <span><span class="nl-dot" style="background:#10b981"></span> Active Node</span>
            <span><span class="nl-dot" style="background:#ef4444"></span> Alerted</span>
        </div>
    </div>`;

    setTimeout(() => { startNetmap(); }, 30);
}

// Register page
if (window.PAGES) {
    window.PAGES.netmap = renderNetmap;
}

/* ────────────────────────────────────────────── */
/*  Core engine                                    */
/* ────────────────────────────────────────────── */
function startNetmap() {
    const cvs = document.getElementById("netCanvas");
    if (!cvs) return;

    const ctx = cvs.getContext("2d", { alpha: false });
    let w = 0, h = 0;
    let dpr = window.devicePixelRatio || 1;

    /* ── State ── */
    let nodes = [];               // flat array, stable order
    let nodeById = new Map();     // id → node ref
    let edges = [];
    let layoutDirty = true;       // true → must recompute positions
    let prevNodeCount = -1;
    let renderDirty = true;       // true → must repaint
    let animId = null;
    let alive = true;             // false after teardown
    let hasData = false;          // true once first successful fetch completes

    /* ── Resize (throttled) ── */
    let resizeScheduled = false;
    const applySize = () => {
        const cont = cvs.parentElement;
        if (!cont) return;
        w = cont.clientWidth;
        h = cont.clientHeight;
        cvs.width = w * dpr;
        cvs.height = h * dpr;
        cvs.style.width = w + "px";
        cvs.style.height = h + "px";
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        layoutDirty = true;
    };
    const onResize = () => {
        if (resizeScheduled) return;
        resizeScheduled = true;
        requestAnimationFrame(() => { resizeScheduled = false; applySize(); });
    };
    window.addEventListener("resize", onResize);
    applySize();

    /* ── Dragging ── */
    let dragNode = null;
    let dragOffX = 0, dragOffY = 0;

    /* ── Pre-rendered glow bitmaps (replaces expensive ctx.shadowBlur) ── */
    const glowCache = {};         // color → OffscreenCanvas/Canvas

    function getGlow(color, r) {
        const key = color + "|" + r;
        if (glowCache[key]) return glowCache[key];
        const s = (r + 16) * 2;               // bitmap size includes glow spread
        const oc = document.createElement("canvas");
        oc.width = s * dpr;
        oc.height = s * dpr;
        const gc = oc.getContext("2d");
        gc.setTransform(dpr, 0, 0, dpr, 0, 0);
        const cx = s / 2, cy = s / 2;
        const grad = gc.createRadialGradient(cx, cy, r * 0.4, cx, cy, r + 14);
        grad.addColorStop(0, color);
        grad.addColorStop(0.55, color);
        grad.addColorStop(1, "transparent");
        gc.fillStyle = grad;
        gc.fillRect(0, 0, s, s);
        glowCache[key] = { canvas: oc, size: s };
        return glowCache[key];
    }

    /* ── Layout: circular, computed only when topology changes ── */
    function computeLayout() {
        if (!w || !h || nodes.length === 0) return;
        const cx = w / 2, cy = h / 2;
        const radius = Math.min(w, h) / 2.8;
        const count = nodes.length;
        for (let i = 0; i < count; i++) {
            const n = nodes[i];
            // Only assign position if the node has no dragged position
            if (n._dragged) continue;
            const angle = (Math.PI * 2 * i) / count;
            n.x = cx + Math.cos(angle) * radius;
            n.y = cy + Math.sin(angle) * radius;
        }
        layoutDirty = false;
        renderDirty = true;
    }

    /* ── Data merge — incremental diff ── */
    function mergeData(raw) {
        let incoming = raw.nodes || [];
        const incomingIds = new Set();
        let topologyChanged = false;

        // If backend returned nothing, inject a placeholder local host node
        if (incoming.length === 0) {
            incoming = [{ id: "localhost", packets: 0, ports: 0, risk: 0, alerted: false, type: "internal", country: "Local", _placeholder: true }];
        }

        for (const n of incoming) {
            incomingIds.add(n.id);
            if (nodeById.has(n.id)) {
                const ex = nodeById.get(n.id);
                ex.packets = n.packets ?? ex.packets;
                ex.ports = n.ports ?? ex.ports;
                ex.risk = n.risk ?? ex.risk;
                ex.alerted = n.alerted ?? ex.alerted;
                ex.type = n.type ?? ex.type;
                ex.country = n.country ?? ex.country;
                ex._placeholder = !!n._placeholder;
            } else {
                n.x = w / 2;
                n.y = h / 2;
                n._dragged = false;
                nodeById.set(n.id, n);
                topologyChanged = true;
            }
        }

        // Remove departed nodes
        for (const id of nodeById.keys()) {
            if (!incomingIds.has(id)) {
                nodeById.delete(id);
                topologyChanged = true;
            }
        }

        nodes = Array.from(nodeById.values());
        // Accept both 'edges' and 'links' keys from backend
        edges = raw.edges || raw.links || [];

        if (topologyChanged || nodes.length !== prevNodeCount) {
            prevNodeCount = nodes.length;
            layoutDirty = true;
        }
        renderDirty = true;
        hasData = true;
    }

    let lastTheme = null;

    /* ── Render (called via rAF only when dirty) ── */
    function render() {
        if (!alive) return;
        animId = requestAnimationFrame(render);

        const currentTheme = document.documentElement.classList.contains("light") ? "light" : "dark";
        if (currentTheme !== lastTheme) {
            lastTheme = currentTheme;
            renderDirty = true;
        }

        if (!renderDirty) return;
        renderDirty = false;

        if (layoutDirty) computeLayout();

        const isLight = currentTheme === "light";
        const theme = {
            bg: isLight ? "#f0f2f5" : "#06080d",
            waitingText: isLight ? "#475569" : "#64748b",
            edgeNormal: isLight ? "rgba(37,99,235,0.3)" : "rgba(59,130,246,0.15)",
            edgeAlert: isLight ? "rgba(220,38,38,0.4)" : "rgba(239,68,68,0.25)",
            spokeColor: isLight ? "rgba(0,0,0,0.06)" : "rgba(255,255,255,0.04)",
            hubText: isLight ? "#ffffff" : "#ffffff",
            labelText: isLight ? "#64748b" : "#94a3b8",
            subLabelText: isLight ? "#94a3b8" : "#64748b"
        };

        // If the theme changed, we must re-render exactly at 60fps instead of resting
        // Setting alpha to false means we draw a solid rect over everything
        ctx.fillStyle = theme.bg;
        ctx.fillRect(0, 0, w, h);

        const cx = w / 2, cy = h / 2;
        const isOnlyPlaceholder = nodes.length === 1 && nodes[0]._placeholder;

        if (nodes.length === 0 || isOnlyPlaceholder) {
            ctx.font = "12px 'JetBrains Mono', monospace";
            ctx.fillStyle = theme.waitingText;
            ctx.textAlign = "center";
            ctx.fillText(hasData ? "No network activity detected yet" : "Connecting to detection engine…", cx, cy - 80);

            if (nodes.length === 0) {
                // If API hasn't responded at all yet, draw a manual dim hub
                ctx.globalAlpha = 0.3;
                ctx.beginPath();
                ctx.arc(cx, cy - 30, 18, 0, Math.PI * 2);
                ctx.fillStyle = "#3b82f6";
                ctx.fill();
                ctx.font = "bold 10px 'JetBrains Mono', monospace";
                ctx.fillStyle = "#3b82f6";
                ctx.fillText("X-NIDS", cx, cy - 6);
                ctx.globalAlpha = 1;
                return;
            }
        }

        /* 1. Edges (batched by color to minimize state changes) */
        ctx.lineWidth = 1;
        // Normal edges
        ctx.beginPath();
        ctx.strokeStyle = theme.edgeNormal;
        for (const e of edges) {
            const src = nodeById.get(e.source);
            const tgt = nodeById.get(e.target);
            if (!src || !tgt) continue;
            if (src.alerted || tgt.alerted) continue;   // drawn separately
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
        }
        ctx.stroke();

        // Alerted edges
        ctx.beginPath();
        ctx.strokeStyle = theme.edgeAlert;
        for (const e of edges) {
            const src = nodeById.get(e.source);
            const tgt = nodeById.get(e.target);
            if (!src || !tgt) continue;
            if (!(src.alerted || tgt.alerted)) continue;
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
        }
        ctx.stroke();

        /* 2. Spokes to center hub */
        ctx.beginPath();
        ctx.strokeStyle = theme.spokeColor;
        for (const n of nodes) {
            if (n.alerted) continue;
            ctx.moveTo(cx, cy);
            ctx.lineTo(n.x, n.y);
        }
        ctx.stroke();

        ctx.beginPath();
        ctx.strokeStyle = theme.edgeAlert;
        for (const n of nodes) {
            if (!n.alerted) continue;
            ctx.moveTo(cx, cy);
            ctx.lineTo(n.x, n.y);
        }
        ctx.stroke();

        /* 3. Center hub (glow via cached bitmap) */
        const hubGlow = getGlow("#3b82f6", 18);
        ctx.drawImage(hubGlow.canvas,
            cx - hubGlow.size / 2, cy - hubGlow.size / 2,
            hubGlow.size, hubGlow.size);
        ctx.beginPath();
        ctx.arc(cx, cy, 18, 0, Math.PI * 2);
        ctx.fillStyle = "#3b82f6";
        ctx.fill();

        ctx.font = "bold 10px 'JetBrains Mono', monospace";
        ctx.fillStyle = theme.hubText;
        ctx.textAlign = "center";
        ctx.fillText("X-NIDS", cx, cy + 30);

        /* 4. Nodes — draw all green first, then red (minimise fillStyle swaps) */
        ctx.textAlign = "left";

        // Blue nodes (Internal)
        ctx.fillStyle = "#3b82f6";
        ctx.beginPath();
        for (const n of nodes) {
            if (n.alerted || n.type !== "internal") continue;
            const r = nodeRadius(n);
            ctx.moveTo(n.x + r, n.y);
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        }
        ctx.fill();

        // Green nodes (External Active)
        ctx.fillStyle = "#10b981";
        ctx.beginPath();
        for (const n of nodes) {
            if (n.alerted || n.type === "internal") continue;
            const r = nodeRadius(n);
            ctx.moveTo(n.x + r, n.y);
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        }
        ctx.fill();

        // Red (alerted) nodes — with glow
        for (const n of nodes) {
            if (!n.alerted) continue;
            const r = nodeRadius(n);
            const g = getGlow("#ef4444", r);
            ctx.drawImage(g.canvas,
                n.x - g.size / 2, n.y - g.size / 2,
                g.size, g.size);
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.fillStyle = "#ef4444";
            ctx.fill();
        }

        /* 5. Labels (single font set) */
        ctx.font = "10px 'JetBrains Mono', monospace";
        ctx.fillStyle = theme.labelText;
        for (const n of nodes) {
            const r = nodeRadius(n);
            ctx.fillText(n.id, n.x + r + 5, n.y + 3);
        }

        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillStyle = theme.subLabelText;
        for (const n of nodes) {
            if (n.packets <= 0) continue;
            const r = nodeRadius(n);
            ctx.fillText(n.packets + " pkts", n.x + r + 5, n.y + 14);
        }
    }

    function nodeRadius(n) {
        return Math.min(25, Math.max(8, (n.packets / 100) + 6));
    }

    /* ── Pointer / drag handling ── */
    function hitTest(mx, my) {
        for (let i = nodes.length - 1; i >= 0; i--) {
            const n = nodes[i];
            const dx = mx - n.x, dy = my - n.y;
            const r = nodeRadius(n) + 4;   // small padding
            if (dx * dx + dy * dy <= r * r) return n;
        }
        return null;
    }

    cvs.addEventListener("pointerdown", e => {
        const rect = cvs.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const hit = hitTest(mx, my);
        if (hit) {
            dragNode = hit;
            dragOffX = mx - hit.x;
            dragOffY = my - hit.y;
            hit._dragged = true;
            cvs.setPointerCapture(e.pointerId);
            e.preventDefault();
        }
    });

    cvs.addEventListener("pointermove", e => {
        if (!dragNode) {
            // Hover cursor
            const rect = cvs.getBoundingClientRect();
            const hit = hitTest(e.clientX - rect.left, e.clientY - rect.top);
            cvs.style.cursor = hit ? "grab" : "default";
            return;
        }
        const rect = cvs.getBoundingClientRect();
        dragNode.x = e.clientX - rect.left - dragOffX;
        dragNode.y = e.clientY - rect.top - dragOffY;
        renderDirty = true;
    });

    const endDrag = () => {
        if (dragNode) {
            cvs.style.cursor = "default";
        }
        dragNode = null;
    };
    cvs.addEventListener("pointerup", endDrag);
    cvs.addEventListener("pointercancel", endDrag);

    /* ── Data polling (decoupled from rendering) ── */
    if (window.netmapInterval) clearInterval(window.netmapInterval);

    async function fetchData() {
        try {
            const res = await fetch("/api/netmap");
            const d = await res.json();
            mergeData(d);
        } catch (e) {
            // silent — keep showing last state
        }
    }

    fetchData();                                       // initial fetch
    window.netmapInterval = setInterval(fetchData, 3000);  // poll every 3 s

    /* ── Start render loop ── */
    animId = requestAnimationFrame(render);

    /* ── Cleanup hook (called when navigating away) ── */
    window._netmapCleanup = () => {
        alive = false;
        if (animId) cancelAnimationFrame(animId);
        if (window.netmapInterval) { clearInterval(window.netmapInterval); window.netmapInterval = null; }
        window.removeEventListener("resize", onResize);
        window._netmapCleanup = null;
    };
}
