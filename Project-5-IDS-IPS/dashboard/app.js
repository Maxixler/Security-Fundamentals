let totalAnalyzed = 0;
let totalBlocked = 0;
let lastLogTime = 0;

async function fetchLogs() {
    try {
        const res = await fetch('/api/logs');
        const data = await res.json();
        
        const stream = document.getElementById('log-stream');
        
        let newLogs = data.logs.filter(log => log.timestamp > lastLogTime);
        if(newLogs.length > 0) {
            lastLogTime = newLogs[newLogs.length - 1].timestamp;
            
            newLogs.forEach(log => {
                totalAnalyzed++;
                if(log.status !== "PASSED") totalBlocked++;
                
                const timeStr = new Date(log.timestamp * 1000).toISOString().substr(11, 8);
                const div = document.createElement('div');
                div.className = `log-entry log-${log.status.replace(' ', '_')}`;
                
                let safePayload = log.payload.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                div.innerHTML = `[${timeStr}] ${log.src_ip} -> ${log.dst_ip}:${log.dst_port} | [${log.status}] | ${log.protocol} | Payload: <span style="opacity:0.6">${safePayload}</span> | Action: ${log.reason}`;
                
                stream.appendChild(div);
                
                if(stream.childNodes.length > 30) {
                    stream.removeChild(stream.firstChild);
                }
            });
            
            stream.scrollTop = stream.scrollHeight;
        }
        
        document.getElementById('total-pkts').innerText = totalAnalyzed;
        document.getElementById('total-blocks').innerText = totalBlocked;
        
        const bannedList = document.getElementById('banned-list');
        bannedList.innerHTML = '';
        data.banned_ips.forEach(ip => {
            const li = document.createElement('li');
            li.innerHTML = `[BANNED] <strong>${ip}</strong>`;
            bannedList.appendChild(li);
        });

    } catch(err) {
        console.error("Backend offline", err);
    }
}

setInterval(fetchLogs, 800);
