function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderServerDashboard(stats, safeHost) {
  if (!stats) return '';
  const reqps = Number(stats?.live?.requestsPerSecond || 0).toFixed(2);
  const reqpm = Number(stats?.live?.requestsLastMinute || 0);
  const blocked24 = Number(stats?.kpi?.blocked24h || 0);
  const passed24 = Number(stats?.kpi?.passed24h || 0);
  const topIps = (Array.isArray(stats?.topIps) ? stats.topIps : []).slice(0, 8);
  return `<div class="shell" id="server-dashboard-shell">
    <aside class="sidebar">
      <div class="side-title">Ryzeon Shield</div>
      <div class="side-sub">Live Control Panel</div>
      <div class="side-host">${safeHost}</div>
      <nav class="side-nav">
        <button class="tab-btn active" data-tab="overview">Overview</button>
        <button class="tab-btn" data-tab="threats">Threats</button>
        <button class="tab-btn" data-tab="traffic">Traffic</button>
        <button class="tab-btn" data-tab="topips">Top IPs</button>
        <button class="tab-btn" data-tab="profile">Profile</button>
        <button class="tab-btn" data-tab="settings">Settings</button>
      </nav>
      <div class="side-foot">Session active</div>
    </aside>
    <main class="main">
  <div class="wrap" id="server-dashboard">
    <div class="top"><div><div class="title">Ryzeon Shield Live Dashboard</div><div class="muted">Host: ${safeHost} • Session active</div></div><div><button id="refreshBtn" class="btn">Refresh</button> <button id="logoutBtn" class="btn">Logout</button></div></div>
    <div class="grid">
      <section class="card kpi"><div class="sub">Live requests/sec</div><div class="val">${reqps}</div><div class="sub">Last minute total: ${reqpm}</div></section>
      <section class="card kpi"><div class="sub">Blocked (24h)</div><div class="val" style="color:var(--bad)">${blocked24}</div></section>
      <section class="card kpi"><div class="sub">Passed (24h)</div><div class="val" style="color:var(--ok)">${passed24}</div></section>
      <section class="card kpi"><div class="sub">Top IPs</div><div class="sub">${topIps.length}</div></section>
      <section class="card full"><div class="sub">Top Attacking IPs</div><div class="list" style="margin-top:8px">${topIps.length ? topIps.map(r => `<div class="row"><span>${escapeHtml(r.ip || 'N/A')}</span><span>${Number(r.count || 0)} hits</span></div>`).join('') : '<div class="muted">No recent attack data.</div>'}</div></section>
    </div>
  </div>
  </main>
  </div>`;
}

export function htmlShieldStats(host, initialStats = null) {
  const safeHost = escapeHtml(host || 'N/A');
  const hasInitialStats = !!initialStats;
  const initialStatsJson = JSON.stringify(initialStats || null);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Shield Stats — Ryzeon Shield</title>
  <style>
    :root{--bg:#070f1e;--bg2:#0d1a34;--card:rgba(17,27,47,.86);--line:rgba(255,255,255,.08);--txt:#e9f1ff;--muted:#9fb0d0;--a:#56a0ff;--b:#00bcbc;--ok:#2ecc71;--bad:#ff6b6b}
    *{box-sizing:border-box}
    body{margin:0;min-height:100vh;background:radial-gradient(circle at 10% 10%,rgba(86,160,255,.2),transparent 36%),radial-gradient(circle at 85% 90%,rgba(0,188,188,.2),transparent 34%),linear-gradient(160deg,var(--bg),var(--bg2));font-family:Inter,Segoe UI,Arial,sans-serif;color:var(--txt)}
    .shell{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
    .sidebar{border-right:1px solid var(--line);background:rgba(10,18,34,.78);backdrop-filter:blur(10px);padding:18px 14px;position:sticky;top:0;height:100vh}
    .side-title{font-weight:800;font-size:1.05rem;letter-spacing:.2px}
    .side-sub{font-size:.82rem;color:var(--muted);margin-top:4px}
    .side-host{margin-top:14px;font-size:.78rem;color:#c8d6f4;word-break:break-all;background:rgba(255,255,255,.04);padding:8px;border-radius:8px;border:1px solid var(--line)}
    .side-nav{margin-top:14px;display:grid;gap:8px}
    .tab-btn{display:block;width:100%;text-align:left;text-decoration:none;color:#dbe7ff;background:rgba(255,255,255,.03);border:1px solid transparent;padding:9px 10px;border-radius:9px;font-size:.9rem;cursor:pointer;transition:all .18s ease}
    .tab-btn.active,.tab-btn:hover{border-color:rgba(86,160,255,.45);background:rgba(86,160,255,.12);transform:translateX(2px)}
    .side-foot{position:absolute;left:14px;right:14px;bottom:16px;font-size:.78rem;color:var(--muted)}
    .main{min-width:0}
    .wrap{max-width:1280px;margin:0 auto;padding:20px}
    .top{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}
    .title{font-size:1.2rem;font-weight:700}
    .muted{color:var(--muted)}
    .btn{border:1px solid rgba(86,160,255,.4);background:rgba(86,160,255,.14);color:#eaf2ff;padding:9px 12px;border-radius:10px;cursor:pointer}
    .btn:hover{background:rgba(86,160,255,.22)}
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;backdrop-filter:blur(10px)}
    .kpi{grid-column:span 3}
    .wide{grid-column:span 6}
    .full{grid-column:span 12}
    .val{font-size:1.8rem;font-weight:700;line-height:1.2}
    .sub{font-size:.84rem;color:var(--muted)}
    .list{display:grid;gap:8px}
    .row{display:flex;justify-content:space-between;gap:10px;font-size:.9rem}
    .bar{height:8px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}
    .bar > span{display:block;height:100%;background:linear-gradient(90deg,var(--a),var(--b))}
    .heat{display:grid;grid-template-columns:repeat(24,1fr);gap:4px;margin-top:8px}
    .cell{height:16px;border-radius:4px;background:rgba(255,255,255,.06);position:relative}
    .legend{display:flex;justify-content:space-between;font-size:.76rem;color:var(--muted);margin-top:8px}
    .login{max-width:420px;margin:16vh auto 0;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px}
    .input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid rgba(255,255,255,.14);background:rgba(0,0,0,.25);color:var(--txt);outline:none}
    .input:focus{border-color:rgba(86,160,255,.6)}
    .err{color:var(--bad);font-size:.84rem;min-height:1.1rem;margin-top:8px}
    .chip{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:.75rem;border:1px solid var(--line);background:rgba(255,255,255,.04)}
    .tab-content{animation:fadeTab .2s ease}
    @keyframes fadeTab{from{opacity:.45;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
    .mini-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
    .mini{padding:10px;border-radius:10px;border:1px solid var(--line);background:rgba(255,255,255,.03)}
    .mini .k{font-size:.76rem;color:var(--muted)}
    .mini .v{font-size:1.05rem;font-weight:700;margin-top:4px}
    .switch{display:flex;justify-content:space-between;align-items:center;padding:10px;border-radius:10px;border:1px solid var(--line);background:rgba(255,255,255,.03)}
    .switch input{accent-color:#56a0ff}
    canvas{width:100%;height:280px}
    @media (max-width:1080px){.shell{grid-template-columns:1fr}.sidebar{position:relative;height:auto;border-right:none;border-bottom:1px solid var(--line)}.side-foot{position:static;margin-top:10px}}
    @media (max-width:980px){.kpi{grid-column:span 6}.wide{grid-column:span 12}}
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
</head>
<body>
  <div id="app">
    ${hasInitialStats ? renderServerDashboard(initialStats, safeHost) : ''}
    ${hasInitialStats ? '' : `
    <div class="login">
      <div class="title">Ryzeon Shield Admin</div>
      <div class="muted" style="margin:6px 0 14px">Host: ${safeHost}</div>
      <form id="loginForm" method="post" action="/__shield/admin/login">
        <input id="pwd" name="password" class="input" type="password" placeholder="Enter admin password"/>
        <button id="loginBtn" type="submit" class="btn" style="margin-top:10px;width:100%">Login</button>
      </form>
      <div class="err" id="err"></div>
    </div>
    `}
  </div>
<script>
(() => {
  const SAFE_HOST = ${JSON.stringify(safeHost)};
  const INITIAL_STATS = ${initialStatsJson};
  const TOKEN_KEY = 'shield_admin_jwt';
  const app = document.getElementById('app');
  let chart = null;
  let activeTab = 'overview';

  function renderFatal(message){
    if(!app) return;
    app.innerHTML = '<div class="login">'
      + '<div class="title">Dashboard Error</div>'
      + '<div class="muted" style="margin:6px 0 10px">Host: ' + SAFE_HOST + '</div>'
      + '<div class="err" style="display:block">' + esc(message || 'Unknown runtime error') + '</div>'
      + '<button class="btn" style="margin-top:10px;width:100%" onclick="location.reload()">Reload</button>'
      + '</div>';
  }

  window.addEventListener('error', function(e){
    const msg = (e && (e.message || (e.error && e.error.message))) || 'Script error';
    renderFatal(msg);
  });

  function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[m]));}
  function flag(cc){
    const code = String(cc||'').toUpperCase();
    if(!/^[A-Z]{2}$/.test(code)) return '🌍';
    return String.fromCodePoint(...code.split('').map(c=>127397+c.charCodeAt(0)));
  }
  function getToken(){ try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; } }
  function setToken(v){ try { localStorage.setItem(TOKEN_KEY, v); } catch {} }
  function clearToken(){ try { localStorage.removeItem(TOKEN_KEY); } catch {} }

  async function api(path, opts={}){
    const token = getToken();
    const headers = { 'content-type': 'application/json', ...(opts.headers||{}) };
    if (token) headers.authorization = 'Bearer ' + token;
    const res = await fetch(path, { ...opts, headers });
    const text = await res.text();
    let data = {};
    try { data = JSON.parse(text || '{}'); } catch {}
    if (!res.ok) {
      const err = new Error(data.error || ('HTTP ' + res.status));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function renderLogin(error=''){
    app.innerHTML = '<div class="login">'
      + '<div class="title">Ryzeon Shield Admin</div>'
      + '<div class="muted" style="margin:6px 0 14px">Host: ' + SAFE_HOST + '</div>'
      + '<form id="loginForm" method="post" action="/__shield/admin/login">'
      + '<input id="pwd" name="password" class="input" type="password" placeholder="Enter admin password"/>'
      + '<button id="loginBtn" type="submit" class="btn" style="margin-top:10px;width:100%">Login</button>'
      + '</form>'
      + '<div class="err" id="err">' + esc(error) + '</div>'
      + '</div>';
    const form = document.getElementById('loginForm');
    if (!form) return;
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      const password = document.getElementById('pwd').value || '';
      try {
        const r = await fetch('/__shield/admin/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ password }),
        });
        const data = await r.json();
        if (!r.ok || !data.token) throw new Error(data.error || 'Login failed');
        setToken(data.token);
        await renderDashboard();
      } catch (e) {
        renderLogin(e.message || 'Login failed');
      }
    };
  }

  function buildHeatmap(hours){
    const max = Math.max(1, ...hours.map(x => Number(x.blocked || 0)));
    return '<div class="heat">' + hours.map((h) => {
      const v = Number(h.blocked || 0);
      const o = Math.max(.08, v / max);
      return '<div class="cell" title="' + esc((h.hour||'??') + ':00  blocked=' + v) + '" style="background:rgba(255,107,107,' + o.toFixed(3) + ')"></div>';
    }).join('') + '</div><div class="legend"><span>00:00</span><span>23:00</span></div>';
  }

  function renderLine(stats){
    const el = document.getElementById('bpChart');
    if (!el) return;
    const labels = (stats.hourly || []).map(x => x.hour + ':00');
    const blocked = (stats.hourly || []).map(x => Number(x.blocked || 0));
    const passed = (stats.hourly || []).map(x => Number(x.passed || 0));
    if (chart) chart.destroy();
    chart = new Chart(el, {
      type: 'line',
      data: {
        labels,
        datasets: [
          { label: 'Blocked', data: blocked, borderColor: '#ff6b6b', backgroundColor: 'rgba(255,107,107,.16)', tension: .3, fill: true },
          { label: 'Passed', data: passed, borderColor: '#2ecc71', backgroundColor: 'rgba(46,204,113,.14)', tension: .3, fill: true },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#dbe7ff' } } },
        scales: {
          x: { ticks: { color: '#9fb0d0' }, grid: { color: 'rgba(255,255,255,.06)' } },
          y: { ticks: { color: '#9fb0d0' }, grid: { color: 'rgba(255,255,255,.06)' }, beginAtZero: true },
        },
      },
    });
  }

  function bindSidebar(){
    const btns = app.querySelectorAll('.tab-btn[data-tab]');
    btns.forEach((btn) => {
      btn.addEventListener('click', () => {
        activeTab = String(btn.getAttribute('data-tab') || 'overview');
        renderDashboard();
      });
    });
  }

  function tabOverview(stats, topCountries, countryMax, topIps, reqps, reqpm, blocked24, passed24, ratio){
    return '<div class="grid tab-content">'
      + '<section class="card kpi"><div class="sub">Live requests/sec</div><div class="val">' + reqps.toFixed(2) + '</div><div class="sub">Last minute total: ' + reqpm + '</div></section>'
      + '<section class="card kpi"><div class="sub">Blocked (24h)</div><div class="val" style="color:var(--bad)">' + blocked24 + '</div><div class="sub">Threat ratio: ' + ratio + '%</div></section>'
      + '<section class="card kpi"><div class="sub">Passed (24h)</div><div class="val" style="color:var(--ok)">' + passed24 + '</div><div class="sub">Shield version: ' + esc(stats.version || 'v3') + '</div></section>'
      + '<section class="card kpi"><div class="sub">Unique attacking IPs</div><div class="val">' + Number(stats.kpi?.uniqueAttackIps24h || 0) + '</div><div class="sub">Countries active: ' + Number(stats.kpi?.activeCountries24h || 0) + '</div></section>'
      + '<section class="card wide"><div class="sub">Threat Heatmap (blocked per hour)</div>' + buildHeatmap(stats.heatmap || []) + '</section>'
      + '<section class="card wide"><div class="sub">Country Map (Top Countries)</div><div class="list" style="margin-top:8px">'
      + topCountries.map(c => {
          const v = Number(c.count || 0);
          const p = Math.max(4, Math.round((v / countryMax) * 100));
          return '<div><div class="row"><span>' + flag(c.country) + ' ' + esc(c.country || 'N/A') + '</span><span>' + v + '</span></div><div class="bar"><span style="width:' + p + '%"></span></div></div>';
        }).join('')
      + '</div></section>'
      + '<section class="card full"><div class="sub">Blocked vs Passed (24h)</div><div style="height:300px;margin-top:8px"><canvas id="bpChart"></canvas></div></section>'
      + '<section class="card full"><div class="sub">Top Attacking IPs</div><div class="list" style="margin-top:8px">'
      + (topIps.length ? topIps.map(r => '<div class="row"><span>' + esc(r.ip || 'N/A') + '</span><span>' + Number(r.count || 0) + ' hits</span></div>').join('') : '<div class="muted">No recent attack data.</div>')
      + '</div></section>'
      + '</div>';
  }

  function tabThreats(stats){
    return '<div class="grid tab-content">'
      + '<section class="card full"><div class="sub">Threat Intelligence Snapshot</div><div class="mini-grid" style="margin-top:10px">'
      + '<div class="mini"><div class="k">Blocked 24h</div><div class="v" style="color:var(--bad)">' + Number(stats.kpi?.blocked24h || 0) + '</div></div>'
      + '<div class="mini"><div class="k">Unique Attack IPs</div><div class="v">' + Number(stats.kpi?.uniqueAttackIps24h || 0) + '</div></div>'
      + '<div class="mini"><div class="k">Active Countries</div><div class="v">' + Number(stats.kpi?.activeCountries24h || 0) + '</div></div>'
      + '</div></section>'
      + '<section class="card full"><div class="sub">Heatmap</div>' + buildHeatmap(stats.heatmap || []) + '</section>'
      + '</div>';
  }

  function tabTraffic(stats){
    const h = stats.hourly || [];
    const passed = h.reduce((a,b)=>a+Number(b.passed||0),0);
    const blocked = h.reduce((a,b)=>a+Number(b.blocked||0),0);
    return '<div class="grid tab-content">'
      + '<section class="card full"><div class="sub">Traffic Summary (24h)</div><div class="mini-grid" style="margin-top:10px">'
      + '<div class="mini"><div class="k">Total Passed</div><div class="v" style="color:var(--ok)">' + passed + '</div></div>'
      + '<div class="mini"><div class="k">Total Blocked</div><div class="v" style="color:var(--bad)">' + blocked + '</div></div>'
      + '<div class="mini"><div class="k">Current RPS</div><div class="v">' + Number(stats.live?.requestsPerSecond || 0).toFixed(2) + '</div></div>'
      + '</div></section>'
      + '<section class="card full"><div class="sub">Blocked vs Passed (24h)</div><div style="height:300px;margin-top:8px"><canvas id="bpChart"></canvas></div></section>'
      + '</div>';
  }

  function tabTopIps(topIps){
    return '<div class="grid tab-content">'
      + '<section class="card full"><div class="sub">Top Attacking IPs</div><div class="list" style="margin-top:10px">'
      + (topIps.length ? topIps.map((r, i) => '<div class="row"><span>#' + (i+1) + ' ' + esc(r.ip || 'N/A') + '</span><span><span class="chip">' + Number(r.count || 0) + ' hits</span></span></div>').join('') : '<div class="muted">No recent attack data.</div>')
      + '</div></section>'
      + '</div>';
  }

  function tabProfile(){
    const ua = navigator.userAgent || 'Unknown';
    return '<div class="grid tab-content">'
      + '<section class="card full"><div class="sub">Admin Profile</div><div class="mini-grid" style="margin-top:10px">'
      + '<div class="mini"><div class="k">Role</div><div class="v">Shield Admin</div></div>'
      + '<div class="mini"><div class="k">Session</div><div class="v">Active</div></div>'
      + '<div class="mini"><div class="k">Host</div><div class="v">' + SAFE_HOST + '</div></div>'
      + '</div><div class="sub" style="margin-top:10px">User Agent</div><div class="mini" style="margin-top:6px"><div class="k">Client</div><div class="v" style="font-size:.86rem;line-height:1.4">' + esc(ua) + '</div></div></section>'
      + '</div>';
  }

  function tabSettings(){
    return '<div class="grid tab-content">'
      + '<section class="card full"><div class="sub">UI Settings</div><div class="list" style="margin-top:10px">'
      + '<label class="switch"><span>Smooth animations</span><input type="checkbox" checked disabled/></label>'
      + '<label class="switch"><span>Realtime refresh (5s)</span><input type="checkbox" checked disabled/></label>'
      + '<label class="switch"><span>Compact mode</span><input type="checkbox" disabled/></label>'
      + '</div><div class="sub" style="margin-top:10px">Operational controls are available via admin APIs.</div></section>'
      + '</div>';
  }

  async function renderDashboard(seedStats){
    let stats;
    try {
      stats = seedStats || await api('/__shield/admin/dashboard');
    } catch (e) {
      if (e.status === 401) {
        clearToken();
        return renderLogin('Session expired. Login again.');
      }
      return renderLogin(e.message || 'Failed to load dashboard');
    }

    const reqps = Number(stats.live?.requestsPerSecond || 0);
    const reqpm = Number(stats.live?.requestsLastMinute || 0);
    const blocked24 = Number(stats.kpi?.blocked24h || 0);
    const passed24 = Number(stats.kpi?.passed24h || 0);
    const ratio = (blocked24 + passed24) ? Math.round((blocked24 / (blocked24 + passed24)) * 100) : 0;

    const topIps = (stats.topIps || []).slice(0, 8);
    const topCountries = (stats.countries || []).slice(0, 8);
    const countryMax = Math.max(1, ...topCountries.map(x => Number(x.count || 0)));

    let tabHtml = '';
    if (activeTab === 'overview') tabHtml = tabOverview(stats, topCountries, countryMax, topIps, reqps, reqpm, blocked24, passed24, ratio);
    else if (activeTab === 'threats') tabHtml = tabThreats(stats);
    else if (activeTab === 'traffic') tabHtml = tabTraffic(stats);
    else if (activeTab === 'topips') tabHtml = tabTopIps(topIps);
    else if (activeTab === 'profile') tabHtml = tabProfile();
    else if (activeTab === 'settings') tabHtml = tabSettings();
    else tabHtml = tabOverview(stats, topCountries, countryMax, topIps, reqps, reqpm, blocked24, passed24, ratio);

    app.innerHTML = '<div class="shell">'
      + '<aside class="sidebar">'
      + '<div class="side-title">Ryzeon Shield</div>'
      + '<div class="side-sub">Live Control Panel</div>'
      + '<div class="side-host">' + SAFE_HOST + '</div>'
      + '<nav class="side-nav">'
      + '<button class="tab-btn' + (activeTab === 'overview' ? ' active' : '') + '" data-tab="overview">Overview</button>'
      + '<button class="tab-btn' + (activeTab === 'threats' ? ' active' : '') + '" data-tab="threats">Threats</button>'
      + '<button class="tab-btn' + (activeTab === 'traffic' ? ' active' : '') + '" data-tab="traffic">Traffic</button>'
      + '<button class="tab-btn' + (activeTab === 'topips' ? ' active' : '') + '" data-tab="topips">Top IPs</button>'
      + '<button class="tab-btn' + (activeTab === 'profile' ? ' active' : '') + '" data-tab="profile">Profile</button>'
      + '<button class="tab-btn' + (activeTab === 'settings' ? ' active' : '') + '" data-tab="settings">Settings</button>'
      + '</nav>'
      + '<div class="side-foot">Realtime security telemetry</div>'
      + '</aside>'
      + '<main class="main"><div class="wrap">'
      + '<div class="top"><div><div class="title">Ryzeon Shield Live Dashboard</div><div class="muted">Host: ' + SAFE_HOST + ' • Auto-refresh every 5s</div></div><div><button id="refreshBtn" class="btn">Refresh</button> <button id="logoutBtn" class="btn">Logout</button></div></div>'
      + tabHtml
      + '</div></main></div>';

    bindSidebar();

    document.getElementById('refreshBtn').onclick = renderDashboard;
    document.getElementById('logoutBtn').onclick = async () => {
      try { await fetch('/__shield/admin/logout', { method: 'POST' }); } catch {}
      clearToken();
      renderLogin();
    };
    if (document.getElementById('bpChart')) {
      renderLine(stats);
    } else if (chart) {
      chart.destroy();
      chart = null;
    }
  }

  try {
    renderDashboard(INITIAL_STATS || null);

    setInterval(() => {
      if (document.getElementById('bpChart')) renderDashboard();
    }, 5000);
  } catch (e) {
    renderFatal((e && e.message) || 'Initialization failed');
  }
})();
</script>
</body>
</html>`;
}
