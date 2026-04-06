const API = window.location.origin;
let prevAnalyzed = 0;

function updateClock(){document.getElementById("clock").textContent=new Date().toLocaleTimeString("en-US",{hour12:false})}
setInterval(updateClock,1000);updateClock();

async function fetchData(){
    try{
        const res=await fetch(`${API}/api/status`);
        const d=await res.json();
        const stats=d.stats||{};
        document.getElementById("stat-alerts").textContent=stats.alerts_generated||0;
        document.getElementById("stat-analyzed").textContent=stats.packets_analyzed||0;
        document.getElementById("stat-sigs").textContent=stats.signature_matches||0;
        document.getElementById("stat-blocked").textContent=(d.blocked_ips||[]).length;
        document.getElementById("rule-count").textContent=d.rule_count||0;
        const currAnalyzed=stats.packets_analyzed||0;
        document.getElementById("pps").textContent=Math.max(0,currAnalyzed-prevAnalyzed);
        prevAnalyzed=currAnalyzed;
        renderAlerts(d.alerts||[]);
        renderPackets(d.packets||[]);
        renderBlocked(d.blocked_ips||[]);
    }catch(e){console.error(e)}
}

function renderAlerts(alerts){
    const c=document.getElementById("alert-container");
    document.getElementById("alert-count").textContent=alerts.length;
    if(!alerts.length){c.innerHTML='<p class="empty-msg">No threats detected</p>';return}
    let h="";
    alerts.forEach(a=>{
        const ts=a.timestamp?new Date(a.timestamp).toLocaleTimeString("en-US",{hour12:false}):"--";
        const mitre=a.mitre?`<span class="mitre-tag">${a.mitre}</span>`:"";
        h+=`<div class="alert-card sev-${a.severity}">
            <div class="alert-top"><span class="alert-time">${ts}</span><span class="sev-tag">${a.severity}</span></div>
            <div class="alert-name">${esc(a.rule_name||"")}</div>
            <div class="alert-meta">
                <span>SID:${a.rule_sid||"?"}</span>
                <span>${a.src_ip||"?"}→${a.dst_ip||"?"}:${a.dst_port||"?"}</span>
                <span>${a.category||""}</span>
                ${mitre}
            </div>
        </div>`;
    });
    c.innerHTML=h;
}

function renderPackets(packets){
    const tb=document.getElementById("packet-body");
    if(!packets.length){tb.innerHTML="";return}
    let h="";
    packets.forEach(p=>{
        const det=p.detection||{};
        const verdictClass=det.matched?(det.action==="drop"?"verdict-drop":"verdict-alert"):"verdict-pass";
        const verdictText=det.matched?(det.action==="drop"?"DROP":"ALERT"):"PASS";
        h+=`<tr>
            <td><span class="proto-badge proto-${p.protocol}">${p.protocol}</span></td>
            <td>${p.src_ip}:${p.src_port||0}</td>
            <td>${p.dst_ip}:${p.dst_port||0}</td>
            <td>${p.flags||"-"}</td>
            <td>${p.size}B</td>
            <td class="${verdictClass}">${verdictText}</td>
        </tr>`;
    });
    tb.innerHTML=h;
}

function renderBlocked(blocked){
    const c=document.getElementById("banned-container");
    if(!blocked.length){c.innerHTML='<p class="empty-msg">No blocked IPs</p>';return}
    let h="";
    blocked.forEach(b=>{
        h+=`<div class="banned-item">
            <span class="banned-ip">${b.ip}</span>
            <span class="banned-reason">${b.reason}</span>
            <span class="banned-ttl">${b.ttl_remaining}s</span>
        </div>`;
    });
    c.innerHTML=h;
}

// Load rules once
async function loadRules(){
    try{
        const res=await fetch(`${API}/api/rules`);
        const d=await res.json();
        const c=document.getElementById("rules-container");
        let h="";
        (d.rules||[]).forEach(r=>{
            h+=`<div class="rule-item">
                <span class="rule-sid">SID:${r.sid}</span>
                <span class="rule-name">${r.name}</span>
                <span class="rule-sev ${r.severity}">${r.severity}</span>
            </div>`;
        });
        c.innerHTML=h;
    }catch(e){console.error(e)}
}

function esc(s){const d=document.createElement("div");d.textContent=s;return d.innerHTML}

setInterval(fetchData,1500);
fetchData();
loadRules();
