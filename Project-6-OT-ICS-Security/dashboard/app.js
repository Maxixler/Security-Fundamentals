const API=window.location.origin;
function updateClock(){document.getElementById("clock").textContent=new Date().toLocaleTimeString("en-US",{hour12:false})}
setInterval(updateClock,1000);updateClock();

const UNITS={
    boiler:{registers:[100,101,102,103],container:"boiler-gauges",status:"boiler-status"},
    pump:{registers:[200,201,202,203],container:"pump-gauges",status:"pump-status"},
    cooling:{registers:[300,301,302,303],container:"cooling-gauges",status:"cooling-status"},
};

async function fetchData(){
    try{
        const res=await fetch(`${API}/api/status`);
        const d=await res.json();
        const plc=d.plc||{};
        const sec=d.security||{};
        const stats=sec.stats||{};

        // Stats
        document.getElementById("stat-cmds").textContent=stats.commands_analyzed||0;
        document.getElementById("stat-alerts").textContent=stats.alerts_generated||0;
        document.getElementById("stat-blocked").textContent=stats.writes_blocked||0;
        document.getElementById("stat-unauth").textContent=stats.unauthorized_access||0;

        // SIS status
        const sisEl=document.getElementById("sis-status");
        if(plc.emergency){
            sisEl.className="sis-status emergency";
            sisEl.querySelector("span:last-child").textContent="⚠ EMERGENCY SHUTDOWN";
        }else{
            sisEl.className="sis-status";
            sisEl.querySelector("span:last-child").textContent="SIS NORMAL";
        }

        // Render gauges
        const regs=plc.registers||{};
        for(const[unitName,unitDef]of Object.entries(UNITS)){
            renderGauges(unitDef.container,unitDef.registers,regs);
            updateUnitStatus(unitDef.status,unitDef.registers,regs);
        }

        // Alerts
        renderAlerts(sec.alerts||[]);

        // Events
        renderEvents(d.events||[]);
    }catch(e){console.error(e)}
}

function renderGauges(containerId,regAddrs,registers){
    const c=document.getElementById(containerId);
    let h="";
    regAddrs.forEach(addr=>{
        const r=registers[String(addr)];
        if(!r)return;
        const pct=r.max>r.min?((r.value-r.min)/(r.max-r.min)*100):0;
        const clampPct=Math.max(0,Math.min(100,pct));
        const color=pct>90?"var(--critical)":pct>70?"var(--warning)":"var(--accent-light)";
        const rwBadge=r.readonly?"":'<span class="rw-badge">RW</span>';
        h+=`<div class="gauge">
            <div class="gauge-label">${r.name}${rwBadge}</div>
            <div class="gauge-value" style="color:${color}">${r.value}<small style="font-size:.55rem;color:var(--text-muted)"> ${r.unit}</small></div>
            <div class="gauge-bar"><div class="gauge-fill" style="width:${clampPct}%;background:${color}"></div></div>
            <div class="gauge-range"><span>${r.min}</span><span>${r.max}</span></div>
        </div>`;
    });
    c.innerHTML=h;
}

function updateUnitStatus(statusId,regAddrs,registers){
    const el=document.getElementById(statusId);
    let maxPct=0;
    regAddrs.forEach(addr=>{
        const r=registers[String(addr)];
        if(!r||r.max<=r.min)return;
        const pct=(r.value-r.min)/(r.max-r.min)*100;
        if(pct>maxPct)maxPct=pct;
    });
    if(maxPct>90){el.textContent="CRITICAL";el.className="unit-status critical"}
    else if(maxPct>70){el.textContent="WARNING";el.className="unit-status warning"}
    else{el.textContent="NORMAL";el.className="unit-status normal"}
}

function renderAlerts(alerts){
    const c=document.getElementById("alert-container");
    document.getElementById("alert-badge").textContent=alerts.length;
    if(!alerts.length){c.innerHTML='<p class="empty-msg">No security alerts</p>';return}
    let h="";
    alerts.forEach(a=>{
        const ts=a.timestamp?new Date(a.timestamp).toLocaleTimeString("en-US",{hour12:false}):"--";
        h+=`<div class="alert-item sev-${a.severity}">
            <div class="alert-msg">${esc(a.message||"")}</div>
            <div class="alert-meta">
                <span>${ts}</span>
                <span>SRC:${a.source_ip||"?"}</span>
                <span>REG:${a.register||"?"}</span>
                <span>${a.action||""}</span>
            </div>
        </div>`;
    });
    c.innerHTML=h;
}

function renderEvents(events){
    const c=document.getElementById("event-container");
    if(!events.length){c.innerHTML='<p class="empty-msg">Waiting for events...</p>';return}
    let h="";
    events.forEach(e=>{
        h+=`<div class="event-item">
            <span class="evt-time">${e.time||"--"}</span>
            <span class="evt-type ${e.type}">${e.type}</span>
            <span class="evt-msg">${esc(e.message||"")}</span>
        </div>`;
    });
    c.innerHTML=h;
}

function esc(s){const d=document.createElement("div");d.textContent=s;return d.innerHTML}

setInterval(fetchData,1500);
fetchData();
