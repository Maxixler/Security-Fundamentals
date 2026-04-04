async function fetchStats() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('stat-events').innerText = data.total_events || 0;
        document.getElementById('stat-alerts').innerText = data.total_alerts || 0;
    } catch(e) { console.error(e); }
}

async function fetchEvents() {
    try {
        const res = await fetch('/api/events');
        const events = await res.json();
        const tbody = document.querySelector('#events-table tbody');
        tbody.innerHTML = '';
        
        events.forEach(evt => {
            const tr = document.createElement('tr');
            const time = new Date(evt.timestamp).toLocaleTimeString();
            const actionMsg = evt.msg || evt.action;
            tr.innerHTML = `
                <td>${time}</td>
                <td>${evt.source_type}</td>
                <td>${evt.src_ip || 'N/A'}</td>
                <td class="sev-${evt.severity}">${evt.severity}</td>
                <td>${actionMsg}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch(e) { console.error(e); }
}

async function fetchAlerts() {
    try {
        const res = await fetch('/api/alerts');
        const alerts = await res.json();
        const container = document.getElementById('alerts-container');
        container.innerHTML = '';
        
        if (alerts.length === 0) {
            container.innerHTML = '<p style="color:#aaffaa">NO ACTIVE THREATS DETECTED.</p>';
            return;
        }

        alerts.forEach(alert => {
            const time = new Date(alert.timestamp).toLocaleTimeString();
            const div = document.createElement('div');
            div.className = 'alert-card';
            div.innerHTML = `
                <h4>[!] ${alert.rule_name}</h4>
                <div class="alert-meta">TIME: ${time}</div>
                <div class="alert-meta">SEVERITY: ${alert.severity}</div>
                <div>${alert.description}</div>
            `;
            container.appendChild(div);
        });
    } catch(e) { console.error(e); }
}

function updateDashboard() {
    fetchStats();
    fetchEvents();
    fetchAlerts();
}

updateDashboard();
setInterval(updateDashboard, 2000);
