import { useEffect, useState, useCallback } from 'react';
import AlertCard from './components/AlertCard';
import SOCCharts from './components/SOCCharts';
import ReportsHistory from './components/ReportsHistory';
import { fetchSiemAlerts, checkBackendHealth } from './api/vigilanceApi';

const G = `*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{background:#f0f4f8;color:#1a202c;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}`;

function LiveClock() {
  const [t, setT] = useState(new Date());
  useEffect(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id); }, []);
  return (
    <div style={{textAlign:'right'}}>
      <div style={{fontSize:'15px',fontWeight:700,color:'#e2e8f0',fontFamily:'monospace'}}>{t.toLocaleTimeString('en-IN',{hour12:false})}</div>
      <div style={{fontSize:'10px',color:'#90cdf4'}}>{t.toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'})}</div>
    </div>
  );
}

export default function App({ onLogout }) {
  const [alerts, setAlerts]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [backendOk, setBackendOk] = useState(null);
  const [filter, setFilter]   = useState('ALL');
  const [search, setSearch]   = useState('');
  const [sort, setSort]       = useState('level_desc');
  const [tab, setTab]         = useState('queue');

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    const ok = await checkBackendHealth();
    setBackendOk(ok);
    if (!ok) { setLoading(false); setError('Cannot reach FastAPI on port 8000.\n\nRun:\n  cd ~/vigilance-ai && source vigilance-env/bin/activate\n  cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000'); return; }
    try { setAlerts(await fetchSiemAlerts()); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  // Auto-refresh disabled — use manual Refresh button

  const C = { ALL:alerts.length, CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  alerts.forEach(a => { const l=parseInt(a?.rule?.level??0,10); if(l>=12)C.CRITICAL++; else if(l>=8)C.HIGH++; else if(l>=4)C.MEDIUM++; else C.LOW++; });

  let list = alerts.filter(a => {
    const l=parseInt(a?.rule?.level??0,10);
    const mf = filter==='ALL'||( filter==='CRITICAL'&&l>=12)||(filter==='HIGH'&&l>=8&&l<12)||(filter==='MEDIUM'&&l>=4&&l<8)||(filter==='LOW'&&l<4);
    const q=search.toLowerCase();
    const ms=!q||[a?.rule?.description,a?.agent?.name,a?.agent?.ip,a?.id].some(v=>(v||'').toLowerCase().includes(q));
    return mf&&ms;
  });
  list=[...list].sort((a,b)=>{ const la=parseInt(a?.rule?.level??0,10),lb=parseInt(b?.rule?.level??0,10); return sort==='level_desc'?lb-la:sort==='level_asc'?la-lb:(a?.id||'').localeCompare(b?.id||''); });

  const TABS=[{k:'queue',l:'🛡 Alert Queue'},{k:'analytics',l:'📊 KPI Dashboard'},{k:'reports',l:'📋 Reports History'}];
  const FTRS=[{k:'ALL',l:'All',c:'#4a5568'},{k:'CRITICAL',l:'Critical',c:'#c53030'},{k:'HIGH',l:'High',c:'#c05621'},{k:'MEDIUM',l:'Medium',c:'#b7791f'},{k:'LOW',l:'Low',c:'#276749'}];
  const SCOLS={CRITICAL:'#c53030',HIGH:'#c05621',MEDIUM:'#b7791f',LOW:'#276749'};
  const SBGS={CRITICAL:'#fff5f5',HIGH:'#fffaf0',MEDIUM:'#fffff0',LOW:'#f0fff4'};

  return (
    <>
      <style>{G}</style>

      {/* NAVBAR */}
      <header style={{background:'linear-gradient(135deg,#0f2044,#1a365d)',padding:'0 28px',height:'64px',display:'flex',alignItems:'center',justifyContent:'space-between',position:'sticky',top:0,zIndex:100,boxShadow:'0 2px 16px rgba(0,0,0,0.3)'}}>
        <div style={{display:'flex',alignItems:'center',gap:'12px'}}>
          <img src="/logo.png" alt="logo" style={{height:'44px',width:'44px',objectFit:'contain',filter:'drop-shadow(0 0 10px rgba(99,179,237,0.7))'}}/>
          <div>
            <div style={{fontSize:'17px',fontWeight:800,color:'#fff',lineHeight:1.2}}>Vigilance AI</div>
            <div style={{fontSize:'9px',color:'#90cdf4',letterSpacing:'0.12em',textTransform:'uppercase'}}>Autonomous Security Surveillance</div>
          </div>
        </div>
        <div style={{display:'flex',gap:'4px',background:'rgba(255,255,255,0.08)',borderRadius:'8px',padding:'4px'}}>
          {TABS.map(t=>(
            <button key={t.k} onClick={()=>setTab(t.k)} style={{padding:'7px 16px',borderRadius:'6px',border:'none',cursor:'pointer',fontSize:'12px',fontWeight:700,background:tab===t.k?'#fff':'transparent',color:tab===t.k?'#1a365d':'rgba(255,255,255,0.7)',transition:'all 0.15s'}}>{t.l}</button>
          ))}
        </div>
        <div style={{display:'flex',alignItems:'center',gap:'16px'}}>
          <LiveClock/>
          <div style={{display:'flex',alignItems:'center',gap:'6px',padding:'5px 12px',borderRadius:'20px',background:backendOk?'rgba(56,161,105,0.15)':'rgba(229,62,62,0.15)',border:`1px solid ${backendOk?'#38a169':'#e53e3e'}`}}>
            <span style={{width:'7px',height:'7px',borderRadius:'50%',background:backendOk?'#38a169':'#e53e3e',display:'inline-block',boxShadow:backendOk?'0 0 8px #38a169':'none'}}/>
            <span style={{fontSize:'11px',fontWeight:700,color:backendOk?'#9ae6b4':'#fc8181'}}>{backendOk?'API ONLINE':'API OFFLINE'} :8000</span>
          </div>
          <button onClick={load} disabled={loading} style={{padding:'7px 14px',background:'rgba(255,255,255,0.1)',color:'#fff',border:'1px solid rgba(255,255,255,0.2)',borderRadius:'8px',fontSize:'12px',fontWeight:600,cursor:loading?'default':'pointer'}}>⟳ Refresh</button>
          <button onClick={onLogout} style={{padding:'7px 14px',background:'rgba(229,62,62,0.15)',color:'#fc8181',border:'1px solid rgba(229,62,62,0.3)',borderRadius:'8px',fontSize:'12px',fontWeight:600,cursor:'pointer'}}>⏻ Logout</button>
        </div>
      </header>

      {/* STAT STRIP */}
      <div style={{background:'#fff',borderBottom:'1px solid #e2e8f0',padding:'10px 28px'}}>
        <div style={{maxWidth:'1200px',margin:'0 auto',display:'flex',gap:'10px',flexWrap:'wrap',alignItems:'center'}}>
          {[{l:'Total Alerts',v:C.ALL,c:'#2b6cb0',bg:'#ebf8ff',b:'#90cdf4'},{l:'Critical',v:C.CRITICAL,c:'#c53030',bg:'#fff5f5',b:'#fc8181'},{l:'High',v:C.HIGH,c:'#c05621',bg:'#fffaf0',b:'#fbd38d'},{l:'Medium',v:C.MEDIUM,c:'#b7791f',bg:'#fffff0',b:'#f6e05e'},{l:'Low',v:C.LOW,c:'#276749',bg:'#f0fff4',b:'#9ae6b4'}].map(s=>(
            <div key={s.l} style={{display:'flex',alignItems:'center',gap:'8px',background:s.bg,border:`1px solid ${s.b}`,borderRadius:'8px',padding:'8px 16px'}}>
              <div style={{fontSize:'10px',color:'#718096',textTransform:'uppercase',letterSpacing:'0.06em'}}>{s.l}</div>
              <div style={{fontSize:'22px',fontWeight:800,color:s.c,lineHeight:1}}>{s.v}</div>
            </div>
          ))}
          <div style={{marginLeft:'auto',fontSize:'11px',color:'#a0aec0',display:'flex',alignItems:'center',gap:'6px'}}>
            <span style={{width:'7px',height:'7px',borderRadius:'50%',background:'#38a169',display:'inline-block'}}/>
            Mistral 7B · 697 MITRE techniques · Manual refresh
          </div>
        </div>
      </div>

      <main style={{maxWidth:'1200px',margin:'0 auto',padding:'24px 24px 60px'}}>

        {!loading&&error&&(
          <div style={{padding:'20px',background:'#fff5f5',border:'1px solid #fc8181',borderRadius:'10px',borderLeft:'4px solid #e53e3e',marginBottom:'20px'}}>
            <div style={{fontSize:'14px',fontWeight:700,color:'#c53030',marginBottom:'8px'}}>✕ Backend Unreachable</div>
            <pre style={{fontSize:'12px',color:'#718096',whiteSpace:'pre-wrap',lineHeight:1.7}}>{error}</pre>
          </div>
        )}

        {/* KPI TAB */}
        {tab==='analytics'&&!loading&&!error&&(
          <div style={{animation:'fadeIn 0.3s ease'}}>
            <div style={{marginBottom:'20px'}}>
              <h2 style={{fontSize:'18px',fontWeight:700,color:'#1a202c',marginBottom:'3px'}}>SOC Dashboard — KPI Overview</h2>
              <p style={{fontSize:'12px',color:'#a0aec0'}}>Real-time analytics · Mistral 7B · MITRE ATT&CK v14</p>
            </div>
            <SOCCharts alerts={alerts}/>
          </div>
        )}
        {/* REPORTS TAB */}
        {tab==='reports'&&(
          <ReportsHistory />
        )}

        {/* QUEUE TAB */}
        {tab==='queue'&&(
          <div style={{animation:'fadeIn 0.3s ease'}}>
            <div style={{display:'flex',gap:'10px',marginBottom:'14px',flexWrap:'wrap',alignItems:'center'}}>
              <div style={{position:'relative',flex:1,minWidth:'220px'}}>
                <span style={{position:'absolute',left:'11px',top:'50%',transform:'translateY(-50%)',color:'#a0aec0'}}>🔍</span>
                <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search host, IP, description, alert ID…"
                  style={{width:'100%',padding:'9px 12px 9px 32px',border:'1px solid #e2e8f0',borderRadius:'8px',fontSize:'13px',color:'#2d3748',background:'#fff',outline:'none'}}/>
              </div>
              <select value={sort} onChange={e=>setSort(e.target.value)} style={{padding:'9px 14px',border:'1px solid #e2e8f0',borderRadius:'8px',fontSize:'13px',color:'#4a5568',background:'#fff',cursor:'pointer'}}>
                <option value="level_desc">Severity ↓ High First</option>
                <option value="level_asc">Severity ↑ Low First</option>
                <option value="id_asc">Alert ID ↑</option>
              </select>
              <div style={{display:'flex',gap:'6px',flexWrap:'wrap'}}>
                {FTRS.map(f=>(
                  <button key={f.k} onClick={()=>setFilter(f.k)} style={{padding:'7px 14px',borderRadius:'20px',border:`1.5px solid ${filter===f.k?f.c:'#e2e8f0'}`,background:filter===f.k?f.c:'#fff',color:filter===f.k?'#fff':f.c,fontSize:'12px',fontWeight:700,cursor:'pointer',transition:'all 0.15s'}}>
                    {f.l} ({C[f.k]})
                  </button>
                ))}
              </div>
            </div>

            {!loading&&!error&&<div style={{fontSize:'12px',color:'#a0aec0',marginBottom:'10px'}}>Showing <strong style={{color:'#4a5568'}}>{list.length}</strong> of {alerts.length} alerts{search&&<> · "<strong style={{color:'#2b6cb0'}}>{search}</strong>"</>}</div>}

            {loading&&[1,2,3].map(i=><div key={i} style={{height:'100px',background:'#fff',border:'1px solid #e2e8f0',borderRadius:'10px',marginBottom:'12px',animation:`pulse 1.4s ease-in-out ${i*0.15}s infinite`}}/>)}

            {!loading&&!error&&list.length===0&&<div style={{textAlign:'center',padding:'60px',color:'#a0aec0',fontSize:'14px',background:'#fff',borderRadius:'10px',border:'1px solid #e2e8f0'}}>{search?`No alerts match "${search}"`:'No alerts in this category.'}</div>}

            {!loading&&!error&&list.map((alert,i)=>(
              <div key={alert?.id||i} style={{animation:`fadeIn 0.3s ease ${i*0.06}s both`}}>
                <AlertCard key={alert.id} alert={alert} index={i}/>
              </div>
            ))}
          </div>
        )}
      </main>

      <footer style={{background:'#0f2044',borderTop:'1px solid #1a365d',color:'#4a6fa5',textAlign:'center',padding:'14px',fontSize:'11px',letterSpacing:'0.04em'}}>
        <img src="/logo.png" alt="" style={{height:'16px',verticalAlign:'middle',marginRight:'8px',opacity:0.5}}/>
        Vigilance AI — Autonomous Security Surveillance · B.Tech Major Project · Mistral 7B + MITRE ATT&CK v14
      </footer>
    </>
  );
}
