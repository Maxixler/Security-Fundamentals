/**
 * NetScan Dashboard - Application Logic
 * ======================================
 * Handles all frontend interactions, API calls to Flask backend,
 * and dynamic UI updates for the network scanner dashboard.
 */

const API_BASE = window.location.origin;

// ==================== STATE ====================
let appState = {
    discoveredHosts: [],
    scanResults: null,
    services: [],
    warnings: 0,
};

// ==================== INITIALIZATION ====================
document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    loadLocalInfo();
    createToastContainer();
});

function createToastContainer() {
    if (!document.querySelector(".toast-container")) {
        const container = document.createElement("div");
        container.className = "toast-container";
        document.body.appendChild(container);
    }
}

// ==================== NAVIGATION ====================
function initNavigation() {
    document.querySelectorAll(".nav-link").forEach((link) => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const page = link.dataset.page;
            switchPage(page);
        });
    });
}

function switchPage(pageName) {
    // Update nav links
    document.querySelectorAll(".nav-link").forEach((l) => l.classList.remove("active"));
    const activeLink = document.querySelector(`[data-page="${pageName}"]`);
    if (activeLink) activeLink.classList.add("active");

    // Update pages
    document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
    const activePage = document.getElementById(`page-${pageName}`);
    if (activePage) activePage.classList.add("active");
}

// ==================== API CALLS ====================
async function apiCall(endpoint, method = "GET", data = null) {
    const options = {
        method,
        headers: { "Content-Type": "application/json" },
    };
    if (data) options.body = JSON.stringify(data);

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        if (error.message.includes("Failed to fetch")) {
            showToast("Cannot connect to server. Make sure the backend is running.", "error");
        }
        throw error;
    }
}

async function loadLocalInfo() {
    try {
        const info = await apiCall("/api/local-info");
        document.getElementById("local-ip").textContent = info.local_ip;
        document.getElementById("local-subnet").textContent = info.local_subnet;

        // Pre-fill targets with local subnet
        const discoverTarget = document.getElementById("discover-target");
        const quickTarget = document.getElementById("quick-target");
        if (discoverTarget && !discoverTarget.value) discoverTarget.value = info.local_subnet;
        if (quickTarget && !quickTarget.value) quickTarget.placeholder = info.local_subnet;
    } catch (e) {
        document.getElementById("local-ip").textContent = "Offline";
        document.getElementById("local-subnet").textContent = "N/A";
    }
}

// ==================== HOST DISCOVERY ====================
async function discoverHosts() {
    const target = document.getElementById("discover-target").value.trim();
    const method = document.getElementById("discover-method").value;
    const timeout = parseFloat(document.getElementById("discover-timeout").value);

    if (!target) {
        showToast("Please enter a target network", "error");
        return;
    }

    const btn = document.getElementById("btn-discover");
    setButtonLoading(btn, true);
    showProgress("Discovering hosts on " + target + "...");

    try {
        const result = await apiCall("/api/discover", "POST", { target, method, timeout });
        
        appState.discoveredHosts = result.hosts;
        updateStats();
        renderHostsTable(result.hosts);
        
        showToast(`Found ${result.count} active hosts`, "success");
        addLogEntry(`Host discovery complete: ${result.count} hosts found on ${target}`);
        updateRecentResults("Host Discovery", target, `${result.count} hosts found`);

        // Switch to results page
        switchPage("results");
    } catch (e) {
        showToast("Discovery failed: " + e.message, "error");
    } finally {
        setButtonLoading(btn, false);
        hideProgress();
    }
}

// ==================== PORT SCANNING ====================
async function scanPorts() {
    const target = document.getElementById("scan-target").value.trim();
    const profile = document.getElementById("scan-profile").value;
    const timeout = parseFloat(document.getElementById("scan-timeout").value);

    if (!target) {
        showToast("Please enter a target IP", "error");
        return;
    }

    const btn = document.getElementById("btn-scan");
    setButtonLoading(btn, true);
    showProgress(`Scanning ports on ${target} (${profile} profile)...`);

    try {
        const result = await apiCall("/api/scan", "POST", { target, profile, timeout });

        appState.scanResults = result;
        updateStats();
        renderPortsTable(result.open_ports, target);
        analyzeSecurityWarnings(result.open_ports);

        showToast(`Found ${result.open_count} open ports on ${target}`, "success");
        addLogEntry(`Port scan complete: ${result.open_count} open, ${result.closed_count} closed, ${result.filtered_count} filtered`);
        updateRecentResults("Port Scan", target, `${result.open_count} open ports`);

        // Auto-detect services
        if (result.open_ports.length > 0) {
            addLogEntry("Starting service detection...");
            const svcResult = await apiCall("/api/detect-services", "POST", {
                target,
                ports: result.open_ports.map((p) => p.port),
            });
            appState.services = svcResult.services;
            renderServicesTable(svcResult.services);
            updateStats();
            addLogEntry(`Service detection: ${svcResult.services.length} services identified`);
        }

        switchPage("results");
    } catch (e) {
        showToast("Scan failed: " + e.message, "error");
    } finally {
        setButtonLoading(btn, false);
        hideProgress();
    }
}

// ==================== FULL SCAN ====================
async function fullScan() {
    const target = document.getElementById("discover-target").value.trim() || 
                   document.getElementById("scan-target").value.trim();
    
    if (!target) {
        showToast("Please enter a target", "error");
        return;
    }

    const btn = document.getElementById("btn-full-scan");
    setButtonLoading(btn, true);
    showProgress(`Full scan on ${target}...`);

    try {
        addLogEntry(`Starting full network scan on ${target}`);
        const result = await apiCall("/api/full-scan", "POST", { target, profile: "common" });

        appState.discoveredHosts = result.discovered_hosts;
        renderHostsTable(result.discovered_hosts);

        // Process all host scans
        let totalOpen = 0;
        let allServices = [];
        let allPorts = [];
        
        for (const scan of result.host_scans) {
            totalOpen += scan.open_count;
            allPorts.push(...scan.open_ports.map(p => ({ ...p, host: scan.target })));
            if (scan.services) {
                allServices.push(...scan.services);
            }
        }

        appState.scanResults = { open_count: totalOpen };
        appState.services = allServices;
        
        renderPortsTable(allPorts);
        renderServicesTable(allServices);
        analyzeSecurityWarnings(allPorts);
        updateStats();

        showToast(`Full scan complete: ${result.total_hosts} hosts, ${totalOpen} open ports`, "success");
        updateRecentResults("Full Scan", target, `${result.total_hosts} hosts, ${totalOpen} ports`);

        switchPage("results");
    } catch (e) {
        showToast("Full scan failed: " + e.message, "error");
    } finally {
        setButtonLoading(btn, false);
        hideProgress();
    }
}

// ==================== QUICK SCAN ====================
async function quickScan() {
    const target = document.getElementById("quick-target").value.trim();
    if (!target) {
        showToast("Please enter a target", "error");
        return;
    }

    // Set target in scanner page and run
    document.getElementById("scan-target").value = target;
    document.getElementById("discover-target").value = target;
    
    const btn = document.getElementById("btn-quick-scan");
    setButtonLoading(btn, true);

    try {
        // Try host first
        const discoverResult = await apiCall("/api/discover", "POST", {
            target,
            method: "tcp",
            timeout: 1.0,
        });

        appState.discoveredHosts = discoverResult.hosts;
        renderHostsTable(discoverResult.hosts);

        // Scan ports on first host (or target itself)
        const scanTarget = discoverResult.hosts.length > 0 
            ? discoverResult.hosts[0].ip 
            : target;

        const scanResult = await apiCall("/api/scan", "POST", {
            target: scanTarget,
            profile: "common",
            timeout: 1.0,
        });

        appState.scanResults = scanResult;
        renderPortsTable(scanResult.open_ports, scanTarget);
        analyzeSecurityWarnings(scanResult.open_ports);
        updateStats();

        showToast(`Quick scan: ${discoverResult.count} hosts, ${scanResult.open_count} open ports`, "success");
        updateRecentResults("Quick Scan", target, `${scanResult.open_count} open ports`);
        
        switchPage("results");
    } catch (e) {
        showToast("Quick scan failed: " + e.message, "error");
    } finally {
        setButtonLoading(btn, false);
    }
}

// ==================== SUBNET CALCULATOR ====================
async function calculateSubnet() {
    const cidr = document.getElementById("subnet-input").value.trim();
    if (!cidr) {
        showToast("Please enter a CIDR notation", "error");
        return;
    }

    try {
        const info = await apiCall(`/api/subnet-info?cidr=${encodeURIComponent(cidr)}`);
        
        if (info.error) {
            showToast("Invalid CIDR: " + info.error, "error");
            return;
        }

        const grid = document.getElementById("subnet-grid");
        const resultCard = document.getElementById("subnet-result");
        resultCard.style.display = "block";

        grid.innerHTML = `
            <div class="subnet-item">
                <div class="subnet-item-label">Network Address</div>
                <div class="subnet-item-value">${info.network_address}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Broadcast Address</div>
                <div class="subnet-item-value">${info.broadcast_address}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Subnet Mask</div>
                <div class="subnet-item-value">${info.subnet_mask}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Wildcard Mask</div>
                <div class="subnet-item-value">${info.wildcard_mask}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Prefix Length</div>
                <div class="subnet-item-value">/${info.prefix_length}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Total Addresses</div>
                <div class="subnet-item-value">${info.total_hosts.toLocaleString()}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Usable Hosts</div>
                <div class="subnet-item-value">${info.usable_hosts.toLocaleString()}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">First Host</div>
                <div class="subnet-item-value">${info.first_host}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Last Host</div>
                <div class="subnet-item-value">${info.last_host}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Network Class</div>
                <div class="subnet-item-value">Class ${info.network_class}</div>
            </div>
            <div class="subnet-item">
                <div class="subnet-item-label">Private Network</div>
                <div class="subnet-item-value">${info.is_private ? "✅ Yes" : "❌ No (Public)"}</div>
            </div>
        `;
    } catch (e) {
        showToast("Calculation failed: " + e.message, "error");
    }
}

// ==================== UI RENDERING ====================
function updateStats() {
    document.getElementById("total-hosts").textContent = appState.discoveredHosts.length;
    document.getElementById("total-open-ports").textContent = appState.scanResults?.open_count || 0;
    document.getElementById("total-services").textContent = appState.services.length;
    document.getElementById("total-warnings").textContent = appState.warnings;
}

function renderHostsTable(hosts) {
    const tbody = document.getElementById("hosts-tbody");
    
    if (!hosts.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No hosts discovered</td></tr>';
        return;
    }

    tbody.innerHTML = hosts.map((h) => `
        <tr>
            <td><code>${h.ip}</code></td>
            <td><span class="badge badge-open">UP</span></td>
            <td>${h.method}</td>
            <td>${h.rtt_ms}ms</td>
            <td>
                <button class="btn btn-primary btn-small" onclick="scanHost('${h.ip}')">
                    Scan Ports
                </button>
            </td>
        </tr>
    `).join("");
}

function renderPortsTable(ports, targetHost = "") {
    const tbody = document.getElementById("ports-tbody");

    if (!ports.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No open ports found</td></tr>';
        return;
    }

    tbody.innerHTML = ports.map((p) => {
        const hostCol = p.host ? `<code>${p.host}</code>:` : "";
        const otBadge = p.is_ot_port 
            ? `<span class="badge badge-ot">OT/ICS</span>` 
            : "";
        return `
            <tr>
                <td>${hostCol}<strong>${p.port}</strong></td>
                <td><span class="badge badge-open">${p.state}</span></td>
                <td>${p.service || "Unknown"}</td>
                <td>${p.description || ""}</td>
                <td>${p.rtt_ms || "-"}ms</td>
                <td>${otBadge}</td>
            </tr>
        `;
    }).join("");
}

function renderServicesTable(services) {
    const tbody = document.getElementById("services-tbody");
    
    if (!services.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No services detected</td></tr>';
        return;
    }

    tbody.innerHTML = services.map((s) => {
        const sslBadge = s.ssl ? '<span class="badge badge-ssl">SSL</span>' : "No";
        const bannerShort = s.banner ? 
            (s.banner.length > 60 ? s.banner.substring(0, 60) + "..." : s.banner) : "-";
        return `
            <tr>
                <td>${s.port}</td>
                <td>${s.service || "Unknown"}</td>
                <td>${s.version || "-"}</td>
                <td><code>${escapeHtml(bannerShort)}</code></td>
                <td>${sslBadge}</td>
            </tr>
        `;
    }).join("");
}

function analyzeSecurityWarnings(ports) {
    const warningsCard = document.getElementById("warnings-card");
    const warningsList = document.getElementById("warnings-list");
    
    const riskyPorts = {
        23: { severity: "critical", msg: "Telnet is UNENCRYPTED - all data including passwords sent in cleartext. Replace with SSH (port 22)." },
        21: { severity: "high", msg: "FTP transmits credentials in cleartext. Use SFTP or FTPS instead." },
        445: { severity: "high", msg: "SMB/CIFS detected - frequent target for ransomware attacks (WannaCry, NotPetya). Ensure patched and restricted." },
        3389: { severity: "high", msg: "RDP detected - common brute force target. Enable Network Level Authentication (NLA) and use VPN." },
        502: { severity: "critical", msg: "Modbus TCP has NO authentication or encryption. Critical OT/ICS security risk! Isolate behind firewall." },
        161: { severity: "high", msg: "SNMP detected - can leak device configurations. Upgrade to SNMPv3 with authentication." },
        139: { severity: "medium", msg: "NetBIOS can expose system information. Consider disabling if not needed." },
        1433: { severity: "medium", msg: "MSSQL exposed - ensure not accessible from untrusted networks." },
        3306: { severity: "medium", msg: "MySQL exposed - verify authentication and network access controls." },
    };

    let warnings = [];
    for (const port of ports) {
        if (riskyPorts[port.port]) {
            warnings.push({ port: port.port, ...riskyPorts[port.port] });
        }
        if (port.is_ot_port) {
            warnings.push({
                port: port.port,
                severity: "critical",
                msg: `OT/ICS port (${port.ot_protocol || "Industrial"}) accessible. Should be isolated from IT network.`,
            });
        }
    }

    appState.warnings = warnings.length;
    updateStats();

    if (warnings.length === 0) {
        warningsCard.style.display = "none";
        return;
    }

    warningsCard.style.display = "block";
    warningsList.innerHTML = warnings.map((w) => `
        <div class="alert-box alert-${w.severity === 'critical' ? 'critical' : w.severity}">
            <strong>[${w.severity.toUpperCase()}] Port ${w.port}:</strong> ${w.msg}
        </div>
    `).join("");
}

function scanHost(ip) {
    document.getElementById("scan-target").value = ip;
    switchPage("scanner");
    showToast(`Target set to ${ip}. Click 'Scan Ports' to start.`, "info");
}

// ==================== UI UTILITIES ====================
function setButtonLoading(btn, loading) {
    if (loading) {
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Scanning...';
        btn.disabled = true;
    } else {
        btn.innerHTML = btn.dataset.originalText || btn.innerHTML;
        btn.disabled = false;
    }
}

function showProgress(text) {
    const card = document.getElementById("scan-progress-card");
    if (card) {
        card.style.display = "block";
        document.getElementById("progress-text").textContent = text;
        const fill = document.getElementById("scan-progress");
        fill.style.width = "0%";
        // Animate progress
        let width = 0;
        const interval = setInterval(() => {
            width += Math.random() * 5;
            if (width > 90) { clearInterval(interval); return; }
            fill.style.width = width + "%";
        }, 200);
        card.dataset.intervalId = interval;
    }
}

function hideProgress() {
    const card = document.getElementById("scan-progress-card");
    if (card) {
        const fill = document.getElementById("scan-progress");
        fill.style.width = "100%";
        clearInterval(Number(card.dataset.intervalId));
        setTimeout(() => { card.style.display = "none"; }, 1000);
    }
}

function addLogEntry(text, type = "info") {
    const log = document.getElementById("scan-log");
    if (!log) return;
    const entry = document.createElement("div");
    entry.className = `log-entry log-${type === "success" ? "success" : type === "error" ? "error" : ""}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

function updateRecentResults(type, target, summary) {
    const container = document.getElementById("recent-results");
    
    // Remove empty state if present
    const empty = container.querySelector(".empty-state");
    if (empty) container.innerHTML = "";

    const item = document.createElement("div");
    item.style.cssText = `
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.75rem 1rem;
        background: rgba(0,0,0,0.2);
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 3px solid var(--accent-primary);
    `;
    item.innerHTML = `
        <div>
            <strong style="color: var(--accent-primary);">${type}</strong>
            <span style="color: var(--text-secondary); margin-left: 0.5rem;">${target}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span style="color: var(--green); font-size: 0.85rem;">${summary}</span>
            <span style="color: var(--text-muted); font-size: 0.75rem;">${new Date().toLocaleTimeString()}</span>
        </div>
    `;

    container.insertBefore(item, container.firstChild);

    // Keep only last 10
    while (container.children.length > 10) {
        container.removeChild(container.lastChild);
    }
}

function showToast(message, type = "info") {
    const container = document.querySelector(".toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    const icons = {
        success: "✅",
        error: "❌",
        info: "ℹ️",
    };

    toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(100%)";
        toast.style.transition = "all 0.3s ease";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
