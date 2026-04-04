const API = window.location.origin;

function updateTime() {
    const now = new Date();
    document.getElementById('time-display').textContent = now.toLocaleTimeString('en-US', {hour12: false});
}
setInterval(updateTime, 1000);
updateTime();

async function fetchMetrics() {
    try {
        const res = await fetch(`${API}/api/metrics`);
        const result = await res.json();
        
        const dot = document.getElementById('plc-status-dot');
        const text = document.getElementById('plc-status-text');

        if (result.status === "online" && result.data) {
            dot.className = "dot online";
            text.textContent = "PLC ONLINE [127.0.0.1:5020]";
            updateSensors(result.data);
        } else {
            dot.className = "dot offline";
            text.textContent = "PLC OFFLINE / COMM ERROR";
            setOfflineState();
        }
    } catch(e) {
        document.getElementById('plc-status-dot').className = "dot offline";
        document.getElementById('plc-status-text').textContent = "HMI DISCONNECTED";
        setOfflineState();
    }
}

function updateSensors(data) {
    // Temp
    document.getElementById('val-temp').textContent = data.temperature;
    document.getElementById('thresh-temp').textContent = data.threshold_temp;
    updateBar('temp', data.temperature, data.threshold_temp, 500);

    // Pressure
    document.getElementById('val-pressure').textContent = data.pressure;
    document.getElementById('thresh-pressure').textContent = data.threshold_pressure;
    updateBar('pressure', data.pressure, data.threshold_pressure, 150);

    // Valve
    const valveVisual = document.getElementById('valve-visual');
    const valveText = document.getElementById('val-valve');
    if (data.valve_status === 1) {
        valveVisual.classList.add('open');
        valveText.textContent = "STATUS: OPEN [ALARM]";
        valveText.style.color = "var(--danger)";
    } else {
        valveVisual.classList.remove('open');
        valveText.textContent = "STATUS: CLOSED [NORMAL]";
        valveText.style.color = "var(--text-muted)";
    }
}

function updateBar(type, val, thresh, max) {
    const fill = document.getElementById(`bar-${type}`);
    const card = fill.closest('.sensor-card');
    
    let pct = (val / max) * 100;
    if (pct > 100) pct = 100;
    
    fill.style.width = `${pct}%`;
    
    // Status coloring
    card.classList.remove('safe', 'warn', 'danger');
    if (val >= thresh) {
        card.classList.add('danger');
        fill.style.background = "var(--danger)";
    } else if (val >= thresh * 0.8) {
        card.classList.add('warn');
        fill.style.background = "var(--warn)";
    } else {
        card.classList.add('safe');
        fill.style.background = "var(--safe)";
    }
}

function setOfflineState() {
    document.getElementById('val-temp').textContent = "--";
    document.getElementById('val-pressure').textContent = "--";
    /* Keep thresholds as they were or clear them, up to design */
}

async function fetchAlerts() {
    try {
        const res = await fetch(`${API}/api/alerts`);
        const result = await res.json();
        const container = document.getElementById('alerts-container');
        const pulse = document.querySelector('.pulse');

        if (!result.alerts || result.alerts.length === 0) {
            container.innerHTML = '<div class="empty-alerts">Monitoring active. No anomalies detected.</div>';
            pulse.classList.remove('alerting');
            return;
        }

        pulse.classList.add('alerting');
        
        let html = '';
        result.alerts.forEach(a => {
            const time = new Date(a.timestamp).toLocaleTimeString();
            const cls = a.severity.toLowerCase(); // critical, high
            html += `
                <div class="alert-item ${cls}">
                    <div class="alert-time">${time} | ${a.severity}</div>
                    <div class="alert-title">${a.message}</div>
                    <div class="alert-desc">${a.details}</div>
                </div>
            `;
        });
        container.innerHTML = html;
        
    } catch(e) {}
}

// Polling loops
setInterval(fetchMetrics, 1000);
setInterval(fetchAlerts, 2000);
fetchMetrics();
fetchAlerts();
