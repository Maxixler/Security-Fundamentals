let logCount = 0;

async function fetchData() {
    try {
        const res = await fetch("/api/scada_data");
        const data = await res.json();
        
        // Analog Meter Update
        const pVal = data.plc_state[100];
        const rVal = data.plc_state[200];
        
        document.getElementById("val-100").style.width = pVal + "%";
        document.getElementById("val-100").innerText = pVal + "% Valve";
        
        const rpmPercent = Math.min((rVal / 5000) * 100, 100);
        document.getElementById("val-200").style.width = rpmPercent + "%";
        document.getElementById("val-200").innerText = rVal + " RPM";
        
        // Alert Log Update
        if (data.logs.length > logCount || data.logs.length === 30) {
            logCount = data.logs.length;
            const tbody = document.getElementById("log-body");
            tbody.innerHTML = "";
            
            // Reverse loop to show newest Modbus command on top
            for (let i = data.logs.length - 1; i >= 0; i--) {
                const log = data.logs[i];
                const tr = document.createElement("tr");
                if (log.alert) tr.className = "alert-row";
                
                tr.innerHTML = `
                    <td>${log.time}</td>
                    <td><b>${log.tid}</b></td>
                    <td>${log.action}</td>
                    <td>[${log.addr}]</td>
                    <td>${log.val}</td>
                    <td><span class="sev-${log.sev}">${log.sev}</span></td>
                    <td>${log.msg}</td>
                `;
                tbody.appendChild(tr);
            }
        }
        
    } catch(err) {
        console.error("SCADA connection lost", err);
    }
}

setInterval(fetchData, 1000);
