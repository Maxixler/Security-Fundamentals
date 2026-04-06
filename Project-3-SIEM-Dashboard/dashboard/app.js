/**
 * SIEM SOC Dashboard — Frontend Application
 * ============================================
 * Handles real-time data polling, UI rendering, tab navigation,
 * log filtering, search, and MITRE ATT&CK visualization.
 */

const API = window.location.origin;
let currentSourceFilter = "all";
let currentSeverityFilter = "all";
let totalLogsIngested = 0;
let previousAlertCount = 0;

// ─── Clock ─────────────────────────────────────────────────────────────
function updateClock() {
    const now = new Date();
    document.getElementById("system-clock").textContent =
        now.toLocaleTimeString("en-US", { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ─── Tab Navigation ────────────────────────────────────────────────────
document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
        btn.classList.add("active");
        const tabId = btn.dataset.tab;
        document.getElementById(`content-${tabId}`).classList.add("active");
        if (tabId === "mitre") fetchMitreData();
    });
});

// ─── Source Filters ────────────────────────────────────────────────────
document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        currentSourceFilter = btn.dataset.source;
    });
});

// ─── Severity Filters (Alerts Tab) ─────────────────────────────────────
document.querySelectorAll(".severity-filter").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".severity-filter").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        currentSeverityFilter = btn.dataset.severity;
    });
});

// ─── Search ────────────────────────────────────────────────────────────
document.getElementById("search-btn").addEventListener("click", performSearch);
document.getElementById("log-search-input").addEventListener("keypress", e => {
    if (e.key === "Enter") performSearch();
});

async function performSearch() {
    const query = document.getElementById("log-search-input").value.trim();
    const source = document.getElementById("log-source-filter").value;
    if (!query && !source) return;

    try {
        const res = await fetch(`${API}/api/search`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query, source }),
        });
        const data = await res.json();
        renderSearchResults(data.results, data.total);
    } catch (err) {
        console.error("Search error:", err);
    }
}

function renderSearchResults(results, total) {
    const container = document.getElementById("search-results");
    if (!results || results.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No results found.</p></div>';
        return;
    }

    let html = `<div style="padding:0.5rem 0;font-size:0.8rem;color:var(--text-secondary)">
        Found ${total} results</div>
        <table class="log-table"><thead><tr>
            <th>TIME</th><th>SOURCE</th><th>EVENT TYPE</th><th>SRC IP</th><th>ACTION</th><th>DESCRIPTION</th>
        </tr></thead><tbody>`;

    results.forEach(log => {
        const ts = extractTime(log.timestamp);
        html += `<tr>
            <td>${ts}</td>
            <td><span class="src-badge src-${log.source_type}">${(log.source_type || "").toUpperCase()}</span></td>
            <td>${log.event_type || ""}</td>
            <td>${log.src_ip || "-"}</td>
            <td class="act-${log.action}">${log.action || "-"}</td>
            <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">${log.description || ""}</td>
        </tr>`;
    });

    html += "</tbody></table>";
    container.innerHTML = html;
}

// ─── Main Data Polling ─────────────────────────────────────────────────
async function fetchSiemData() {
    try {
        const res = await fetch(`${API}/api/status`);
        const data = await res.json();

        // Update stats
        const alerts = data.alerts || [];
        const logs = data.recent_logs || [];
        const stats = data.stats || {};

        const critCount = alerts.filter(a => a.severity === "Critical").length;
        const highCount = alerts.filter(a => a.severity === "High").length;

        document.getElementById("stat-critical").textContent = critCount;
        document.getElementById("stat-high").textContent = highCount;
        document.getElementById("stat-total-logs").textContent = stats.total_buffered || 0;

        // Active sources
        let sourcesActive = 0;
        ["firewall", "active_directory", "web_server", "dns", "vpn"].forEach(s => {
            if (stats[s] > 0) sourcesActive++;
        });
        document.getElementById("stat-sources").textContent = sourcesActive;

        // EPS (events per second approximation)
        const totalNow = stats.total_buffered || 0;
        const eps = Math.max(0, totalNow - totalLogsIngested);
        totalLogsIngested = totalNow;
        document.getElementById("eps-counter").textContent = eps;

        // Alert badge
        const alertBadge = document.getElementById("alert-badge");
        alertBadge.textContent = alerts.length;
        alertBadge.style.display = alerts.length > 0 ? "inline" : "none";

        // Render incidents
        renderIncidents(alerts);

        // Render logs (filtered)
        const filteredLogs = currentSourceFilter === "all"
            ? logs
            : logs.filter(l => l.source_type === currentSourceFilter);
        renderLogs(filteredLogs);

        // Render alerts tab (filtered)
        const filteredAlerts = currentSeverityFilter === "all"
            ? alerts
            : alerts.filter(a => a.severity === currentSeverityFilter);
        renderAlertsTab(filteredAlerts);

    } catch (err) {
        document.getElementById("sys-status").querySelector("span:last-child").textContent = "API ERROR";
        document.querySelector(".pulse-dot").style.background = "var(--critical)";
    }
}

// ─── Render Functions ──────────────────────────────────────────────────
function renderIncidents(incidents) {
    const container = document.getElementById("incidents-container");
    document.getElementById("incident-count").textContent = incidents.length;

    if (!incidents || incidents.length === 0) {
        container.innerHTML = `<div class="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <p>Monitoring active. Correlation engine processing events...</p>
        </div>`;
        return;
    }

    let html = "";
    incidents.forEach(inc => {
        const ts = inc.timestamp ? new Date(inc.timestamp).toLocaleTimeString("en-US", { hour12: false }) : "--:--:--";
        const mitre = inc.mitre || {};
        const mitreTag = mitre.technique
            ? `<span class="mitre-tag">${mitre.technique}</span>`
            : "";

        html += `
        <div class="incident-card sev-${inc.severity}">
            <div class="inc-top">
                <span class="inc-time">${ts}</span>
                <span class="inc-sev">${inc.severity}</span>
            </div>
            <div class="inc-desc">${escapeHtml(inc.description || "")}</div>
            <div class="inc-meta">
                <span>SRC: ${inc.src_ip || "N/A"}</span>
                <span>TGT: ${inc.target || "N/A"}</span>
                <span>GEO: ${inc.country || "?"}</span>
                ${mitreTag}
            </div>
        </div>`;
    });
    container.innerHTML = html;
}

function renderLogs(logs) {
    const tbody = document.getElementById("log-body");
    if (!logs || logs.length === 0) {
        tbody.innerHTML = "";
        return;
    }

    let html = "";
    logs.forEach(log => {
        const ts = extractTime(log.timestamp);
        const srcClass = `src-${log.source_type}`;
        const actClass = `act-${log.action}`;
        const sevClass = `sev-${log.severity || 4}`;

        html += `<tr>
            <td>${ts}</td>
            <td><span class="src-badge ${srcClass}">${(log.source_type || "?").toUpperCase()}</span></td>
            <td>${log.event_type || "-"}</td>
            <td>${log.src_ip || log.username || "-"}</td>
            <td class="${actClass}">${log.action || "-"}</td>
            <td><span class="sev-dot ${sevClass}"></span></td>
        </tr>`;
    });
    tbody.innerHTML = html;
}

function renderAlertsTab(alerts) {
    const container = document.getElementById("alerts-detail-container");

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No alerts match the current filter.</p></div>';
        return;
    }

    let html = "";
    alerts.forEach(alert => {
        const mitre = alert.mitre || {};
        const ts = alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "--";
        const sevClass = `sev-${alert.severity}`;

        html += `
        <div class="alert-detail-card ${sevClass}">
            <div class="alert-top">
                <span class="alert-id">${alert.id || "INC-??????"}</span>
                <span class="alert-sev-badge inc-sev" style="background:var(--${alert.severity === 'Critical' ? 'critical' : alert.severity === 'High' ? 'high' : 'medium'});color:#fff">${alert.severity}</span>
            </div>
            <div class="alert-desc">${escapeHtml(alert.description || "")}</div>
            <div class="alert-details">
                <div class="alert-detail-item">
                    <span class="alert-detail-label">Source IP</span>
                    <span class="alert-detail-value">${alert.src_ip || "N/A"}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">Target</span>
                    <span class="alert-detail-value">${alert.target || "N/A"}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">Country</span>
                    <span class="alert-detail-value">${alert.country || "?"}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">Attack Type</span>
                    <span class="alert-detail-value">${alert.attack_type || "unknown"}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">MITRE Tactic</span>
                    <span class="alert-detail-value">${mitre.tactic || "N/A"}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">MITRE Technique</span>
                    <span class="alert-detail-value">${mitre.technique || "N/A"} ${mitre.name ? "— " + mitre.name : ""}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">Timestamp</span>
                    <span class="alert-detail-value">${ts}</span>
                </div>
                <div class="alert-detail-item">
                    <span class="alert-detail-label">Log Source</span>
                    <span class="alert-detail-value">${alert.source || "N/A"}</span>
                </div>
            </div>
        </div>`;
    });
    container.innerHTML = html;
}

// ─── MITRE ATT&CK ─────────────────────────────────────────────────────
async function fetchMitreData() {
    try {
        const res = await fetch(`${API}/api/mitre`);
        const data = await res.json();
        renderMitre(data.mapping || []);
    } catch (err) {
        console.error("MITRE fetch error:", err);
    }
}

function renderMitre(mapping) {
    const grid = document.getElementById("mitre-grid");

    if (!mapping || mapping.length === 0) {
        grid.innerHTML = '<div class="empty-state"><p>No attack techniques detected yet.</p></div>';
        return;
    }

    // Sort by count (highest first)
    mapping.sort((a, b) => (b.count || 0) - (a.count || 0));

    let html = "";
    mapping.forEach(item => {
        html += `
        <div class="mitre-card">
            <div class="mitre-technique">${item.technique || "?"}</div>
            <div class="mitre-name">${item.name || "Unknown"}</div>
            <div class="mitre-tactic">Tactic: ${item.tactic || "Unknown"}</div>
            <div class="mitre-count">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
                ${item.count || 0} detections
            </div>
        </div>`;
    });
    grid.innerHTML = html;
}

// ─── Helpers ───────────────────────────────────────────────────────────
function extractTime(timestamp) {
    if (!timestamp) return "--:--:--";
    if (timestamp.includes("T")) return timestamp.split("T")[1].substring(0, 8);
    const parts = timestamp.split(" ");
    return parts.length > 1 ? parts[1].substring(0, 8) : timestamp.substring(0, 8);
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

// ─── Polling Loop ──────────────────────────────────────────────────────
setInterval(fetchSiemData, 1500);
fetchSiemData();
