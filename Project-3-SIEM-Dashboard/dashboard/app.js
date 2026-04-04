const API = window.location.origin;

async function fetchSiemData() {
    try {
        const res = await fetch(`${API}/api/status`);
        const data = await res.json();
        
        renderIncidents(data.alerts);
        renderLogs(data.recent_logs);
    } catch (err) {
        console.error("SIEM API Error:", err);
    }
}

function renderIncidents(incidents) {
    const container = document.getElementById('incidents-container');
    
    if (incidents.length === 0) {
        container.innerHTML = '<div class="empty-state">Monitoring active. No threats correlated.</div>';
        return;
    }

    let html = '';
    incidents.forEach(inc => {
        html += `
            <div class="incident-card inc-${inc.severity}">
                <div class="inc-header">
                    <span class="inc-time">${inc.timestamp || new Date().toLocaleTimeString()}</span>
                    <span class="inc-badge badge-${inc.severity}">${inc.severity}</span>
                </div>
                <div class="inc-desc">${inc.description}</div>
                <div class="inc-meta">
                    <span>SRC: ${inc.src_ip}</span>
                    <span>TGT: ${inc.target}</span>
                    <span>GEO: ${inc.country}</span>
                </div>
            </div>
        `;
    });
    container.innerHTML = html;
}

function renderLogs(logs) {
    const tbody = document.getElementById('logs-body');
    let html = '';
    
    logs.forEach(log => {
        // Extract time from raw if possible, else just use a generated one
        let timeMatch = log.timestamp.split(" ")[1] || log.timestamp;
        
        let typeBadge = `<span class="src-${log.source}">${log.source.toUpperCase()}</span>`;
        let actionClass = `act-${log.action}`;
        
        html += `
            <tr class="log-row">
                <td>${timeMatch}</td>
                <td>${typeBadge}</td>
                <td>${log.event_type}</td>
                <td>${log.src_ip || log.username || '-'}</td>
                <td class="${actionClass}">${log.action}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Fetch every 1.5 seconds to simulate real-time log ingestion
setInterval(fetchSiemData, 1500);
fetchSiemData();
