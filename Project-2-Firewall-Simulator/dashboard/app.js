const API = window.location.origin;
let refreshInterval = null;

document.addEventListener("DOMContentLoaded", () => {
    initNav();
    loadStats();
    loadRules();
    loadZones();
});

// ========== NAVIGATION ==========
function initNav() {
    document.querySelectorAll(".nav-link").forEach(link => {
        link.addEventListener("click", e => {
            e.preventDefault();
            document.querySelectorAll(".nav-link").forEach(l => l.classList.remove("active"));
            link.classList.add("active");
            document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
            document.getElementById("page-" + link.dataset.page).classList.add("active");
            if (link.dataset.page === "logs") loadLogs();
            if (link.dataset.page === "connections") loadConnections();
        });
    });
}

// ========== API HELPERS ==========
async function api(endpoint, method = "GET", data = null) {
    const opts = { method, headers: { "Content-Type": "application/json" } };
    if (data) opts.body = JSON.stringify(data);
    const res = await fetch(API + endpoint, opts);
    return res.json();
}

// ========== STATS ==========
async function loadStats() {
    try {
        const s = await api("/api/stats");
        document.getElementById("st-total").textContent = s.total_packets;
        document.getElementById("st-allow").textContent = s.allowed;
        document.getElementById("st-deny").textContent = s.denied;
        document.getElementById("st-drop").textContent = s.dropped;
    } catch (e) { /* server not ready */ }
}

// ========== SIMULATION ==========
async function simulate(type, count = 50) {
    toast("Running simulation: " + type + "...", "info");
    try {
        const data = { type, count };
        if (type === "handshake") {
            data.src_ip = "192.168.1.10";
            data.dst_ip = "8.8.8.8";
            data.dst_port = 443;
        }
        const result = await api("/api/simulate", "POST", data);
        loadStats();
        renderRecentTable(result.results);
        toast(`Simulation complete: ${result.allowed} allowed, ${result.denied} denied`, "success");
    } catch (e) { toast("Simulation failed: " + e.message, "error"); }
}

function renderRecentTable(results) {
    const tbody = document.getElementById("recent-tbody");
    if (!results || !results.length) return;
    tbody.innerHTML = results.slice(0, 100).map(r => {
        const p = r.packet;
        const cls = r.action === "ALLOW" ? "badge-allow" : r.action === "DROP" ? "badge-drop" : "badge-deny";
        const time = r.timestamp ? r.timestamp.split("T")[1]?.substring(0, 8) : "";
        return `<tr>
            <td>${time}</td>
            <td><span class="badge ${cls}">${r.action}</span></td>
            <td>${p.protocol}</td>
            <td><code>${p.src_ip}:${p.src_port}</code></td>
            <td><code>${p.dst_ip}:${p.dst_port}</code></td>
            <td>${r.zone_src || "?"} -> ${r.zone_dst || "?"}</td>
            <td style="font-size:.78rem;color:var(--text-secondary)">${(r.reason || "").substring(0, 50)}</td>
        </tr>`;
    }).join("");
}

// ========== STREAM ==========
async function toggleStream(action) {
    try {
        const result = await api("/api/simulate/stream", "POST", { action, pps: 5 });
        document.getElementById("stream-status").textContent = "Stream: " + result.status;
        if (result.status === "started") {
            refreshInterval = setInterval(() => { loadStats(); loadLogs(); }, 2000);
            toast("Traffic stream started", "success");
        } else {
            clearInterval(refreshInterval);
            refreshInterval = null;
            toast("Traffic stream stopped", "info");
        }
    } catch (e) { toast("Stream error: " + e.message, "error"); }
}

// ========== RULES ==========
async function loadRules() {
    try {
        const data = await api("/api/rules");
        const tbody = document.getElementById("rules-tbody");
        tbody.innerHTML = data.rules.map(r => {
            const cls = r.action === "ALLOW" ? "badge-allow" : r.action === "DROP" ? "badge-drop" : "badge-deny";
            const src = (r.src_ip === "any" ? "*" : r.src_ip) + (r.src_port ? ":" + r.src_port : ":*");
            const dst = (r.dst_ip === "any" ? "*" : r.dst_ip) + (r.dst_port ? ":" + r.dst_port : ":*");
            return `<tr>
                <td>${r.rule_id}</td>
                <td>${r.priority}</td>
                <td><strong>${r.name}</strong><br><span style="font-size:.72rem;color:var(--text-muted)">${r.description.substring(0, 45)}</span></td>
                <td><span class="badge ${cls}">${r.action}</span></td>
                <td>${r.protocol}</td>
                <td><code>${src}</code></td>
                <td><code>${dst}</code></td>
                <td>${r.direction}</td>
                <td>${r.hit_count}</td>
                <td>${r.enabled ? '<span class="badge badge-allow">ON</span>' : '<span class="badge badge-deny">OFF</span>'}</td>
            </tr>`;
        }).join("");
    } catch (e) { /* not ready */ }
}

function showAddRuleForm() { document.getElementById("add-rule-form").style.display = "block"; }
function hideAddRuleForm() { document.getElementById("add-rule-form").style.display = "none"; }

async function addRule() {
    const rule = {
        name: document.getElementById("r-name").value,
        priority: parseInt(document.getElementById("r-priority").value),
        action: document.getElementById("r-action").value,
        protocol: document.getElementById("r-protocol").value,
        src_ip: document.getElementById("r-src-ip").value,
        src_port: parseInt(document.getElementById("r-src-port").value),
        dst_ip: document.getElementById("r-dst-ip").value,
        dst_port: parseInt(document.getElementById("r-dst-port").value),
        direction: document.getElementById("r-direction").value,
        description: document.getElementById("r-desc").value,
        enabled: true, log: false,
    };
    try {
        await api("/api/rules", "POST", rule);
        hideAddRuleForm();
        loadRules();
        toast("Rule added successfully", "success");
    } catch (e) { toast("Failed to add rule", "error"); }
}

// ========== ZONES ==========
async function loadZones() {
    try {
        const data = await api("/api/zones");
        // Zone cards
        const grid = document.getElementById("zones-grid");
        grid.innerHTML = data.zones.map(z => `
            <div class="zone-card" style="border-left:3px solid ${z.color}">
                <h3 style="color:${z.color}">${z.name.toUpperCase()}</h3>
                <p>${z.description}</p>
                <div style="font-size:.75rem;color:var(--text-muted)">Trust Level: ${z.trust_level}/100</div>
                <div class="trust-bar"><div class="trust-fill" style="width:${z.trust_level}%;background:${z.color}"></div></div>
                <div class="networks">${z.networks.join(", ")}</div>
            </div>
        `).join("");

        // Zone matrix
        const names = Object.keys(data.matrix);
        let html = '<table class="data-table"><thead><tr><th></th>';
        names.forEach(n => html += `<th>${n}</th>`);
        html += "</tr></thead><tbody>";
        names.forEach(src => {
            html += `<tr><td><strong>${src}</strong></td>`;
            names.forEach(dst => {
                const val = data.matrix[src][dst];
                let cls = val === "ALLOW" ? "badge-allow" : val === "SELF" ? "badge-log" : "badge-deny";
                html += `<td><span class="badge ${cls}">${val}</span></td>`;
            });
            html += "</tr>";
        });
        html += "</tbody></table>";
        document.getElementById("zone-matrix-container").innerHTML = html;
    } catch (e) { /* not ready */ }
}

// ========== TEST PACKET ==========
async function testPacket() {
    const data = {
        src_ip: document.getElementById("t-src-ip").value,
        src_port: parseInt(document.getElementById("t-src-port").value),
        dst_ip: document.getElementById("t-dst-ip").value,
        dst_port: parseInt(document.getElementById("t-dst-port").value),
        protocol: document.getElementById("t-proto").value,
        direction: document.getElementById("t-dir").value,
        tcp_flags: document.getElementById("t-flags").value.split(",").map(f => f.trim()).filter(Boolean),
    };
    try {
        const result = await api("/api/test-packet", "POST", data);
        const card = document.getElementById("test-result-card");
        card.style.display = "block";
        const cls = result.action === "ALLOW" ? "result-allow" : result.action === "DROP" ? "result-drop" : "result-deny";
        document.getElementById("test-result").innerHTML = `
            <div class="test-result-box ${cls}">
                <strong>Action: ${result.action}</strong><br>
                Reason: ${result.reason}<br>
                Zone: ${result.zone_src} -> ${result.zone_dst}<br>
                Connection State: ${result.conn_state || "N/A"}<br>
                Rule: ${result.rule_id || "default policy"}
            </div>`;
        loadStats();
    } catch (e) { toast("Test failed: " + e.message, "error"); }
}

const SCENARIOS = {
    web: { src_ip: "192.168.1.10", src_port: 54321, dst_ip: "8.8.8.8", dst_port: 443, protocol: "TCP", direction: "OUTBOUND", tcp_flags: ["SYN"] },
    dns: { src_ip: "192.168.1.10", src_port: 54321, dst_ip: "172.16.0.10", dst_port: 53, protocol: "UDP", direction: "OUTBOUND", tcp_flags: [] },
    telnet: { src_ip: "203.0.113.5", src_port: 54321, dst_ip: "192.168.1.50", dst_port: 23, protocol: "TCP", direction: "INBOUND", tcp_flags: ["SYN"] },
    ot_modbus: { src_ip: "192.168.1.10", src_port: 54321, dst_ip: "10.10.1.20", dst_port: 502, protocol: "TCP", direction: "FORWARD", tcp_flags: ["SYN"] },
    ot_internal: { src_ip: "10.10.1.10", src_port: 54321, dst_ip: "10.10.2.200", dst_port: 502, protocol: "TCP", direction: "ANY", tcp_flags: ["SYN"] },
    ot_internet: { src_ip: "10.10.1.10", src_port: 54321, dst_ip: "8.8.8.8", dst_port: 443, protocol: "TCP", direction: "OUTBOUND", tcp_flags: ["SYN"] },
    ssh_admin: { src_ip: "10.0.0.5", src_port: 54321, dst_ip: "192.168.1.50", dst_port: 22, protocol: "TCP", direction: "ANY", tcp_flags: ["SYN"] },
    ssh_external: { src_ip: "203.0.113.5", src_port: 54321, dst_ip: "192.168.1.50", dst_port: 22, protocol: "TCP", direction: "INBOUND", tcp_flags: ["SYN"] },
};

async function testScenario(name) {
    const s = SCENARIOS[name];
    if (!s) return;
    // Fill form
    document.getElementById("t-src-ip").value = s.src_ip;
    document.getElementById("t-src-port").value = s.src_port;
    document.getElementById("t-dst-ip").value = s.dst_ip;
    document.getElementById("t-dst-port").value = s.dst_port;
    document.getElementById("t-proto").value = s.protocol;
    document.getElementById("t-dir").value = s.direction;
    document.getElementById("t-flags").value = s.tcp_flags.join(",");
    await testPacket();
}

// ========== LOGS ==========
async function loadLogs() {
    try {
        const data = await api("/api/logs?count=100");
        const tbody = document.getElementById("logs-tbody");
        if (!data.logs || !data.logs.length) return;
        tbody.innerHTML = data.logs.map(r => {
            const p = r.packet;
            const cls = r.action === "ALLOW" ? "badge-allow" : r.action === "DROP" ? "badge-drop" : "badge-deny";
            const stateCls = r.conn_state === "ESTABLISHED" ? "badge-est" : r.conn_state === "INVALID" ? "badge-invalid" : r.conn_state === "NEW" ? "badge-new" : "badge-syn";
            const time = r.timestamp ? r.timestamp.split("T")[1]?.substring(0, 8) : "";
            return `<tr>
                <td>${time}</td>
                <td><span class="badge ${cls}">${r.action}</span></td>
                <td>${p.protocol}</td>
                <td><code>${p.src_ip}:${p.src_port}</code></td>
                <td><code>${p.dst_ip}:${p.dst_port}</code></td>
                <td><span class="badge ${stateCls}">${r.conn_state || "-"}</span></td>
                <td>${r.rule_id || "-"}</td>
                <td style="font-size:.75rem;color:var(--text-secondary)">${(r.reason || "").substring(0, 55)}</td>
            </tr>`;
        }).join("");
    } catch (e) { /* not ready */ }
}

// ========== CONNECTIONS ==========
async function loadConnections() {
    try {
        const data = await api("/api/connections");
        // Stats
        const statsGrid = document.getElementById("conn-stats");
        const s = data.stats;
        statsGrid.innerHTML = `
            <div class="stat-card"><div class="stat-icon st-total"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div><div class="stat-content"><span class="stat-value">${s.active_connections||0}</span><span class="stat-label">Active Connections</span></div></div>
            <div class="stat-card"><div class="stat-icon st-allow"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/></svg></div><div class="stat-content"><span class="stat-value">${s.total_tracked||0}</span><span class="stat-label">Total Tracked</span></div></div>
            <div class="stat-card"><div class="stat-icon st-deny"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></div><div class="stat-content"><span class="stat-value">${s.invalid_packets||0}</span><span class="stat-label">Invalid Packets</span></div></div>`;
        // Table
        const tbody = document.getElementById("conn-tbody");
        if (!data.connections.length) { tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No connections</td></tr>'; return; }
        tbody.innerHTML = data.connections.map(c => {
            const cls = c.state === "ESTABLISHED" ? "badge-est" : c.state === "CLOSED" ? "badge-deny" : "badge-new";
            return `<tr>
                <td><code>${c.src_ip}:${c.src_port}</code></td>
                <td><code>${c.dst_ip}:${c.dst_port}</code></td>
                <td>${c.protocol}</td>
                <td><span class="badge ${cls}">${c.state}</span></td>
                <td>${c.packets_in}</td>
                <td>${c.packets_out}</td>
                <td>${c.age_seconds}s</td>
            </tr>`;
        }).join("");
    } catch (e) { /* not ready */ }
}

// ========== TOAST ==========
function toast(msg, type = "info") {
    const container = document.querySelector(".toast-container");
    const t = document.createElement("div");
    t.className = "toast " + type;
    t.innerHTML = `<span>${msg}</span>`;
    container.appendChild(t);
    setTimeout(() => { t.style.opacity = "0"; t.style.transform = "translateX(100%)"; t.style.transition = ".3s"; setTimeout(() => t.remove(), 300); }, 3500);
}
