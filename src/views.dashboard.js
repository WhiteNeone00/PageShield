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
  const blocked24 = Number(stats?.kpi?.blocked24h || 0);
  const passed24 = Number(stats?.kpi?.passed24h || 0);
  const topIps = (Array.isArray(stats?.topIps) ? stats.topIps : []).slice(0, 5);

  return `<div class="shell" id="server-dashboard-shell">
    <aside class="rail">
      <button class="rail-btn active">🛡️</button>
      <button class="rail-btn">📊</button>
      <button class="rail-btn">⚙️</button>
    </aside>
    <aside class="sidebar">
      <div class="brand">RYZEON</div>
      <div class="brand-sub">Shield Console</div>
      <div class="host-box">${safeHost}</div>
      <nav class="menu">
        <button class="menu-btn active">Overview</button>
        <button class="menu-btn">Threats</button>
        <button class="menu-btn">Traffic</button>
        <button class="menu-btn">Top IPs</button>
        <button class="menu-btn">Profile</button>
        <button class="menu-btn">Settings</button>
      </nav>
      <div class="side-foot">Version: Shield v3</div>
    </aside>
    <main class="main">
      <div class="wrap">
        <header class="topbar">
          <div class="search-wrap"><input class="search" placeholder="Search events, IPs, countries..." disabled></div>
          <div class="profile-pill"><span class="dot"></span> Admin Session</div>
        </header>
        <div class="kpi-grid">
          <section class="glass-card stat-card"><div class="label">Requests / sec</div><div class="value">${reqps}</div></section>
          <section class="glass-card stat-card"><div class="label">Blocked (24h)</div><div class="value bad">${blocked24}</div></section>
          <section class="glass-card stat-card"><div class="label">Passed (24h)</div><div class="value ok">${passed24}</div></section>
        </div>
        <section class="glass-card" style="margin-top:12px">
          <div class="section-title">Top Attacking IPs</div>
          <div class="list" style="margin-top:10px">
            ${topIps.length ? topIps.map(r => `<div class="row"><span>${escapeHtml(r.ip || 'N/A')}</span><span>${Number(r.count || 0)} hits</span></div>`).join('') : '<div class="muted">No recent attack data.</div>'}
          </div>
        </section>
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
    :root{--bg:#050912;--bg2:#091327;--panel:#0b152a;--panel2:#0e1c36;--line:rgba(113,146,216,.2);--line-soft:rgba(113,146,216,.12);--txt:#e8f0ff;--muted:#8ea2c7;--blue:#2f6cff;--blue2:#5a86ff;--ok:#2ddf87;--bad:#ff5f7a;--warn:#ffcb4f}
    *{box-sizing:border-box}
    html,body{height:100%}
    body{margin:0;background:radial-gradient(900px 500px at -5% -5%,rgba(44,92,255,.24),transparent 45%),radial-gradient(700px 380px at 110% 110%,rgba(0,120,255,.18),transparent 46%),linear-gradient(180deg,var(--bg),var(--bg2));color:var(--txt);font-family:Inter,Segoe UI,Arial,sans-serif}
    .shell{min-height:100vh;display:grid;grid-template-columns:72px 250px 1fr}
    .rail{background:rgba(7,13,25,.84);border-right:1px solid var(--line-soft);padding:14px 10px;display:flex;flex-direction:column;align-items:center;gap:10px}
    .rail-btn{width:42px;height:42px;border-radius:12px;border:1px solid var(--line-soft);background:rgba(255,255,255,.02);color:#dbe6ff;cursor:pointer}
    .rail-btn.active,.rail-btn:hover{border-color:rgba(82,132,255,.55);box-shadow:0 0 0 2px rgba(47,108,255,.16) inset;background:rgba(47,108,255,.18)}
    .sidebar{background:linear-gradient(180deg,rgba(8,15,30,.94),rgba(6,12,24,.94));border-right:1px solid var(--line-soft);padding:20px 16px;display:flex;flex-direction:column;min-height:100vh}
    .brand{font-size:2rem;font-weight:900;letter-spacing:.8px}
    .brand-sub{color:var(--muted);font-size:.84rem;margin-top:2px}
    .host-box{margin-top:16px;padding:10px;border:1px solid var(--line-soft);border-radius:12px;background:rgba(255,255,255,.02);font-size:.76rem;color:#b8caf1;word-break:break-all}
    .menu{display:grid;gap:8px;margin-top:14px}
    .menu-btn{display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:12px;border:1px solid transparent;background:rgba(255,255,255,.015);color:#cddcff;cursor:pointer;text-align:left;font-weight:600;transition:all .18s ease}
    .menu-btn:hover,.menu-btn.active{background:linear-gradient(90deg,rgba(47,108,255,.2),rgba(47,108,255,.08));border-color:rgba(72,128,255,.45);transform:translateX(2px)}
    .side-foot{margin-top:auto;color:var(--muted);font-size:.78rem}
    .main{min-width:0}
    .wrap{padding:18px 22px 30px;max-width:1600px;margin:0 auto}
    .topbar{display:flex;justify-content:space-between;align-items:center;gap:14px;margin-bottom:14px}
    .search-wrap{flex:1}
    .search{width:100%;height:46px;border-radius:24px;border:1px solid var(--line-soft);background:rgba(6,12,24,.75);color:var(--txt);padding:0 16px;outline:none}
    .search:focus{border-color:rgba(87,133,255,.65)}
    .profile-pill{display:flex;align-items:center;gap:8px;padding:8px 14px;border:1px solid var(--line-soft);border-radius:999px;background:rgba(255,255,255,.02);font-weight:600}
    .dot{width:8px;height:8px;border-radius:999px;background:var(--ok);box-shadow:0 0 8px var(--ok)}
    .glass-card{background:linear-gradient(180deg,rgba(13,24,47,.84),rgba(9,18,36,.86));border:1px solid var(--line-soft);border-radius:18px;padding:14px;box-shadow:inset 0 0 0 1px rgba(110,145,220,.06)}
    .kpi-grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
    .stat-card{grid-column:span 3;position:relative;overflow:hidden}
    .stat-card:after{content:'';position:absolute;inset:0;background-image:linear-gradient(transparent 97%,rgba(65,111,204,.12) 100%),linear-gradient(90deg,transparent 97%,rgba(65,111,204,.12) 100%);background-size:24px 24px;opacity:.28;pointer-events:none}
    .label{color:var(--muted);font-size:.84rem}
    .value{font-size:1.9rem;font-weight:800;margin-top:8px}
    .value.ok{color:var(--ok)}
    .value.bad{color:var(--bad)}
    .value.warn{color:var(--warn)}
    .section-title{font-size:1.15rem;font-weight:800;font-style:italic;letter-spacing:.2px}
    .section-sub{color:var(--muted);font-size:.84rem;margin-top:4px}
    .split{display:grid;grid-template-columns:1.2fr .8fr;gap:12px;margin-top:12px}
    .list{display:grid;gap:9px}
    .row{display:flex;justify-content:space-between;gap:10px;font-size:.92rem}
    .row .muted{font-size:.85rem}
    .bar{height:8px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden;margin-top:6px}
    .bar>span{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--blue2))}
    .chip{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border:1px solid var(--line-soft);border-radius:999px;background:rgba(255,255,255,.03);font-size:.76rem}
    .top-actions{display:flex;gap:8px;flex-wrap:wrap}
    .btn{border:1px solid rgba(84,132,255,.5);background:linear-gradient(180deg,rgba(49,104,255,.24),rgba(24,65,166,.22));color:#ecf3ff;padding:9px 13px;border-radius:11px;cursor:pointer;font-weight:600}
    .btn:hover{filter:brightness(1.1)}
    .btn.secondary{background:rgba(255,255,255,.02);border-color:var(--line-soft)}
    .btn.warn{border-color:rgba(255,203,79,.48);background:rgba(255,203,79,.15)}
    .btn.danger{border-color:rgba(255,95,122,.48);background:rgba(255,95,122,.15)}
    .tabs-shell{animation:fade .2s ease}
    @keyframes fade{from{opacity:.4;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
    .heat{display:grid;grid-template-columns:repeat(24,1fr);gap:4px;margin-top:10px}
    .cell{height:16px;border-radius:4px;background:rgba(255,255,255,.08)}
    .legend{display:flex;justify-content:space-between;color:var(--muted);font-size:.76rem;margin-top:7px}
    .mini-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
    .mini{padding:10px;border-radius:12px;border:1px solid var(--line-soft);background:rgba(255,255,255,.02)}
    .mini .k{font-size:.78rem;color:var(--muted)}
    .mini .v{font-size:1.1rem;font-weight:700;margin-top:6px}
    .switch{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border:1px solid var(--line-soft);border-radius:12px;background:rgba(255,255,255,.02)}
    .switch input{accent-color:#4b8dff}
    .danger-zone{border-color:rgba(255,95,122,.4);background:rgba(255,95,122,.08)}
    .input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line-soft);background:rgba(0,0,0,.26);color:var(--txt);outline:none}
    .input:focus{border-color:rgba(84,132,255,.64)}
    .muted{color:var(--muted)}
    .login{max-width:430px;margin:15vh auto 0;background:linear-gradient(180deg,rgba(13,24,47,.92),rgba(9,18,36,.92));border:1px solid var(--line-soft);border-radius:16px;padding:20px}
    .login-title{font-size:1.3rem;font-weight:800}
    .err{font-size:.84rem;color:var(--bad);min-height:1.2rem;margin-top:8px}
    .modal-backdrop{position:fixed;inset:0;background:rgba(4,8,14,.72);display:none;align-items:center;justify-content:center;padding:14px;z-index:80}
    .modal-backdrop.show{display:flex}
    .modal{width:min(560px,100%);background:linear-gradient(180deg,#0e1b34,#0a162c);border:1px solid var(--line);border-radius:16px;box-shadow:0 20px 50px rgba(0,0,0,.45)}
    .modal-head{display:flex;align-items:center;justify-content:space-between;padding:14px 14px 10px;border-bottom:1px solid var(--line-soft)}
    .modal-title{font-weight:800;font-size:1.1rem}
    .icon-x{width:32px;height:32px;border:none;background:rgba(255,255,255,.06);border-radius:10px;color:#d9e6ff;cursor:pointer}
    .modal-body{padding:14px;display:grid;gap:10px}
    .toast{position:fixed;right:18px;bottom:18px;z-index:90;min-width:270px;max-width:420px;padding:12px 14px;border-radius:12px;border:1px solid var(--line-soft);background:rgba(9,18,34,.95);color:#e8f0ff;opacity:0;pointer-events:none;transform:translateY(8px);transition:all .2s ease}
    .toast.show{opacity:1;transform:translateY(0)}
    .toast.ok{border-color:rgba(45,223,135,.45)}
    .toast.error{border-color:rgba(255,95,122,.55)}
    canvas{width:100%;height:280px}
    @media (max-width:1200px){.shell{grid-template-columns:64px 220px 1fr}.stat-card{grid-column:span 6}.split{grid-template-columns:1fr}}
    @media (max-width:960px){.shell{grid-template-columns:1fr}.rail{display:none}.sidebar{min-height:auto;border-right:none;border-bottom:1px solid var(--line-soft)}.mini-grid{grid-template-columns:1fr}}
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
</head>
<body>
  <div id="app">
    ${hasInitialStats ? renderServerDashboard(initialStats, safeHost) : ''}
    ${hasInitialStats ? '' : `
    <div class="login">
      <div class="login-title">Ryzeon Shield Admin</div>
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
  let runtimePolicy = null;
  let toastTimer = null;

  function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,function(m){return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m];});}
  function flag(cc){const code=String(cc||'').toUpperCase();if(!/^[A-Z]{2}$/.test(code)) return '🌍';return String.fromCodePoint.apply(String, code.split('').map(c=>127397+c.charCodeAt(0)));}
  function getToken(){ try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; } }
  function setToken(v){ try { localStorage.setItem(TOKEN_KEY, v); } catch {} }
  function clearToken(){ try { localStorage.removeItem(TOKEN_KEY); } catch {} }

  async function api(path, opts={}){
    const token = getToken();
    const headers = { 'content-type': 'application/json', ...(opts.headers || {}) };
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

  function toast(message, type){
    const el = document.getElementById('toast');
    if (!el) return;
    if (toastTimer) clearTimeout(toastTimer);
    el.className = 'toast show ' + (type === 'error' ? 'error' : 'ok');
    el.textContent = message;
    toastTimer = setTimeout(function(){ el.className = 'toast'; }, 2300);
  }

  function renderFatal(message){
    if(!app) return;
    app.innerHTML = '<div class="login">'
      + '<div class="login-title">Dashboard Error</div>'
      + '<div class="muted" style="margin:6px 0 10px">Host: ' + SAFE_HOST + '</div>'
      + '<div class="err" style="display:block">' + esc(message || 'Unknown runtime error') + '</div>'
      + '<button class="btn" style="margin-top:10px;width:100%" onclick="location.reload()">Reload</button>'
      + '</div>';
  }

  function renderLogin(error){
    app.innerHTML = '<div class="login">'
      + '<div class="login-title">Ryzeon Shield Admin</div>'
      + '<div class="muted" style="margin:6px 0 14px">Host: ' + SAFE_HOST + '</div>'
      + '<form id="loginForm" method="post" action="/__shield/admin/login">'
      + '<input id="pwd" name="password" class="input" type="password" placeholder="Enter admin password"/>'
      + '<button id="loginBtn" type="submit" class="btn" style="margin-top:10px;width:100%">Login</button>'
      + '</form>'
      + '<div class="err" id="err">' + esc(error || '') + '</div>'
      + '</div>';

    const form = document.getElementById('loginForm');
    if (!form) return;
    form.onsubmit = async function(ev){
      ev.preventDefault();
      const password = (document.getElementById('pwd') || {}).value || '';
      try {
        const r = await fetch('/__shield/admin/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ password: password }),
        });
        const data = await r.json();
        if (!r.ok || !data.token) throw new Error(data.error || 'Login failed');
        setToken(data.token);
        toast('Login successful', 'ok');
        await renderDashboard();
      } catch (e) {
        renderLogin((e && e.message) || 'Login failed');
      }
    };
  }

  function buildHeatmap(hours){
    const max = Math.max(1, ...hours.map(x => Number(x.blocked || 0)));
    return '<div class="heat">' + hours.map(function(h){
      const v = Number(h.blocked || 0);
      const o = Math.max(.08, v / max);
      return '<div class="cell" title="' + esc((h.hour || '??') + ':00 blocked=' + v) + '" style="background:rgba(255,95,122,' + o.toFixed(3) + ')"></div>';
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
        labels: labels,
        datasets: [
          { label: 'Blocked', data: blocked, borderColor: '#ff5f7a', backgroundColor: 'rgba(255,95,122,.14)', tension: .3, fill: true },
          { label: 'Passed', data: passed, borderColor: '#2ddf87', backgroundColor: 'rgba(45,223,135,.10)', tension: .3, fill: true },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#d5e4ff' } } },
        scales: {
          x: { ticks: { color: '#9cb0d6' }, grid: { color: 'rgba(255,255,255,.06)' } },
          y: { ticks: { color: '#9cb0d6' }, grid: { color: 'rgba(255,255,255,.06)' }, beginAtZero: true },
        },
      },
    });
  }

  function sidebar(){
    const tabs = [
      ['overview','Dashboard'],
      ['threats','Threats'],
      ['traffic','Traffic'],
      ['topips','Top IPs'],
      ['profile','Profile'],
      ['settings','Settings'],
    ];
    return '<aside class="sidebar">'
      + '<div class="brand">RYZEON</div>'
      + '<div class="brand-sub">Shield Console</div>'
      + '<div class="host-box">' + SAFE_HOST + '</div>'
      + '<nav class="menu">'
      + tabs.map(function(t){return '<button class="menu-btn' + (activeTab === t[0] ? ' active' : '') + '" data-tab="' + t[0] + '">' + t[1] + '</button>';}).join('')
      + '</nav>'
      + '<div class="side-foot">Version: Shield v3</div>'
      + '</aside>';
  }

  function rail(){
    return '<aside class="rail">'
      + '<button class="rail-btn active" data-tab="overview">🛡️</button>'
      + '<button class="rail-btn" data-tab="threats">📊</button>'
      + '<button class="rail-btn" data-tab="settings">⚙️</button>'
      + '</aside>';
  }

  function topBar(){
    return '<header class="topbar">'
      + '<div class="search-wrap"><input id="globalSearch" class="search" placeholder="Search events, IPs, countries..." /></div>'
      + '<div class="profile-pill"><span class="dot"></span> Shield Admin</div>'
      + '</header>';
  }

  function overviewTab(stats){
    const reqps = Number(stats.live?.requestsPerSecond || 0);
    const reqpm = Number(stats.live?.requestsLastMinute || 0);
    const blocked24 = Number(stats.kpi?.blocked24h || 0);
    const passed24 = Number(stats.kpi?.passed24h || 0);
    const ratio = (blocked24 + passed24) ? Math.round((blocked24 / (blocked24 + passed24)) * 100) : 0;
    const topCountries = (stats.countries || []).slice(0, 8);
    const topIps = (stats.topIps || []).slice(0, 8);
    const countryMax = Math.max(1, ...topCountries.map(x => Number(x.count || 0)));

    return '<div class="tabs-shell">'
      + '<div class="kpi-grid">'
      + '<section class="glass-card stat-card"><div class="label">Live requests/sec</div><div class="value">' + reqps.toFixed(2) + '</div><div class="muted">Last minute: ' + reqpm + '</div></section>'
      + '<section class="glass-card stat-card"><div class="label">Blocked (24h)</div><div class="value bad">' + blocked24 + '</div><div class="muted">Threat ratio: ' + ratio + '%</div></section>'
      + '<section class="glass-card stat-card"><div class="label">Passed (24h)</div><div class="value ok">' + passed24 + '</div><div class="muted">Host: ' + SAFE_HOST + '</div></section>'
      + '<section class="glass-card stat-card"><div class="label">Unique Attack IPs</div><div class="value warn">' + Number(stats.kpi?.uniqueAttackIps24h || 0) + '</div><div class="muted">Countries: ' + Number(stats.kpi?.activeCountries24h || 0) + '</div></section>'
      + '</div>'
      + '<div class="split">'
      + '<section class="glass-card"><div class="section-title">Threat Heatmap</div><div class="section-sub">Blocked requests per hour</div>' + buildHeatmap(stats.heatmap || []) + '</section>'
      + '<section class="glass-card"><div class="section-title">Top Countries</div><div class="list" style="margin-top:10px">'
      + topCountries.map(function(c){ const v = Number(c.count || 0); const p = Math.max(4, Math.round((v / countryMax) * 100)); return '<div><div class="row"><span>' + flag(c.country) + ' ' + esc(c.country || 'N/A') + '</span><span>' + v + '</span></div><div class="bar"><span style="width:' + p + '%"></span></div></div>'; }).join('')
      + '</div></section>'
      + '</div>'
      + '<section class="glass-card" style="margin-top:12px"><div class="section-title">Blocked vs Passed</div><div style="height:300px;margin-top:8px"><canvas id="bpChart"></canvas></div></section>'
      + '<section class="glass-card" style="margin-top:12px"><div class="section-title">Top Attacking IPs</div><div class="list" style="margin-top:10px">'
      + (topIps.length ? topIps.map(function(r){return '<div class="row"><span>' + esc(r.ip || 'N/A') + '</span><span class="chip">' + Number(r.count || 0) + ' hits</span></div>';}).join('') : '<div class="muted">No recent attack data.</div>')
      + '</div></section>'
      + '</div>';
  }

  function threatsTab(stats){
    return '<div class="tabs-shell">'
      + '<section class="glass-card"><div class="section-title">Threat Intelligence</div><div class="section-sub">Action center for abuse handling</div>'
      + '<div class="top-actions" style="margin-top:12px">'
      + '<button class="btn warn" data-quick-action="suspend">Suspend IP</button>'
      + '<button class="btn secondary" data-quick-action="unsuspend">Unsuspend IP</button>'
      + '<button class="btn danger" data-quick-action="blacklist">Blacklist IP</button>'
      + '<button class="btn" data-quick-action="unblacklist">Unblacklist IP</button>'
      + '</div></section>'
      + '<section class="glass-card" style="margin-top:12px"><div class="section-title">24h Snapshot</div><div class="mini-grid" style="margin-top:10px">'
      + '<div class="mini"><div class="k">Blocked</div><div class="v" style="color:var(--bad)">' + Number(stats.kpi?.blocked24h || 0) + '</div></div>'
      + '<div class="mini"><div class="k">Unique Attack IPs</div><div class="v">' + Number(stats.kpi?.uniqueAttackIps24h || 0) + '</div></div>'
      + '<div class="mini"><div class="k">Active Countries</div><div class="v">' + Number(stats.kpi?.activeCountries24h || 0) + '</div></div>'
      + '</div></section>'
      + '</div>';
  }

  function trafficTab(stats){
    const h = stats.hourly || [];
    const passed = h.reduce((a,b)=>a+Number(b.passed||0),0);
    const blocked = h.reduce((a,b)=>a+Number(b.blocked||0),0);
    return '<div class="tabs-shell">'
      + '<section class="glass-card"><div class="section-title">Traffic Summary</div><div class="mini-grid" style="margin-top:10px">'
      + '<div class="mini"><div class="k">Total Passed</div><div class="v" style="color:var(--ok)">' + passed + '</div></div>'
      + '<div class="mini"><div class="k">Total Blocked</div><div class="v" style="color:var(--bad)">' + blocked + '</div></div>'
      + '<div class="mini"><div class="k">Current RPS</div><div class="v">' + Number(stats.live?.requestsPerSecond || 0).toFixed(2) + '</div></div>'
      + '</div></section>'
      + '<section class="glass-card" style="margin-top:12px"><div class="section-title">Blocked vs Passed (24h)</div><div style="height:300px;margin-top:8px"><canvas id="bpChart"></canvas></div></section>'
      + '</div>';
  }

  function topIpsTab(stats){
    const topIps = (stats.topIps || []).slice(0, 24);
    return '<div class="tabs-shell">'
      + '<section class="glass-card"><div class="section-title">Top Attacking IPs</div><div class="section-sub">Click manage to open a popup action</div><div class="list" style="margin-top:12px">'
      + (topIps.length ? topIps.map(function(r, i){ return '<div class="row"><span>#' + (i + 1) + ' ' + esc(r.ip || 'N/A') + '</span><span><button class="btn secondary" data-manage-ip="' + esc(r.ip || '') + '">Manage</button></span></div>'; }).join('') : '<div class="muted">No recent attack data.</div>')
      + '</div></section>'
      + '</div>';
  }

  function profileTab(stats){
    return '<div class="tabs-shell">'
      + '<section class="glass-card"><div class="section-title">Admin Profile</div><div class="mini-grid" style="margin-top:10px">'
      + '<div class="mini"><div class="k">Role</div><div class="v">Shield Admin</div></div>'
      + '<div class="mini"><div class="k">Session</div><div class="v">Active</div></div>'
      + '<div class="mini"><div class="k">Host</div><div class="v">' + SAFE_HOST + '</div></div>'
      + '</div></section>'
      + '<section class="glass-card" style="margin-top:12px"><div class="section-title">Environment</div><div class="section-sub">Shield version: ' + esc(stats.version || 'v3') + '</div><div class="muted" style="margin-top:8px;word-break:break-all">' + esc(navigator.userAgent || 'Unknown') + '</div></section>'
      + '</div>';
  }

  function settingsTab(policy){
    const p = policy || {};
    const rows = [
      ['protectEnabled','Global protection', !!p.protectEnabled],
      ['rateLimitEnabled','Rate limit', !!p.rateLimitEnabled],
      ['attackBlockEnabled','Attack blocking', !!p.attackBlockEnabled],
      ['vpnBlockEnabled','VPN/Proxy block', !!p.vpnBlockEnabled],
      ['honeypotEnabled','Honeypot system', !!p.honeypotEnabled],
      ['aiCrawlerBlockEnabled','AI crawler block', !!p.aiCrawlerBlockEnabled],
      ['ddosBlockEnabled','DDoS heuristic block', !!p.ddosBlockEnabled],
    ];
    return '<div class="tabs-shell">'
      + '<section class="glass-card"><div class="section-title">Protection Settings</div><div class="section-sub">Toggle live policy controls for Shield</div><div class="list" style="margin-top:12px">'
      + rows.map(function(r){ return '<label class="switch"><span>' + r[1] + '</span><input class="policy-toggle" type="checkbox" data-key="' + r[0] + '" ' + (r[2] ? 'checked' : '') + '></label>'; }).join('')
      + '</div></section>'
      + '<section class="glass-card danger-zone" style="margin-top:12px"><div class="section-title">Danger Zone</div><div class="section-sub">IP actions will open a confirmation popup.</div><div class="top-actions" style="margin-top:10px">'
      + '<button class="btn danger" data-quick-action="suspend">Suspend IP</button>'
      + '<button class="btn secondary" data-quick-action="unsuspend">Unsuspend IP</button>'
      + '</div></section>'
      + '</div>';
  }

  function openModal(html){
    const modal = document.getElementById('modalBackdrop');
    const body = document.getElementById('modalBody');
    if (!modal || !body) return;
    body.innerHTML = html;
    modal.classList.add('show');
    const x = document.getElementById('modalClose');
    if (x) x.onclick = closeModal;
    modal.onclick = function(ev){ if (ev.target === modal) closeModal(); };
  }

  function closeModal(){
    const modal = document.getElementById('modalBackdrop');
    if (modal) modal.classList.remove('show');
  }

  async function submitQuickAction(payload){
    const action = String(payload.action || '');
    const ip = String(payload.ip || '').trim();
    if (!ip) throw new Error('IP is required');

    if (action === 'blacklist') return api('/__shield/admin/blacklist/add', { method: 'POST', body: JSON.stringify({ ip: ip }) });
    if (action === 'unblacklist') return api('/__shield/admin/unblacklist', { method: 'POST', body: JSON.stringify({ ip: ip }) });
    if (action === 'unsuspend') return api('/__shield/admin/ip/unsuspend', { method: 'POST', body: JSON.stringify({ ip: ip }) });
    if (action === 'suspend') {
      const reason = String(payload.reason || 'Admin suspend');
      return api('/__shield/admin/ip/suspend', { method: 'POST', body: JSON.stringify({ ip: ip, reason: reason, permanent: true, durationSeconds: 3600 }) });
    }
    throw new Error('Unsupported action');
  }

  function openQuickActionModal(defaultAction, defaultIp){
    openModal(
      '<div class="muted">Run moderation action against a target IP.</div>'
      + '<label class="muted">Action</label>'
      + '<select id="qaAction" class="input">'
      + '<option value="blacklist" ' + (defaultAction === 'blacklist' ? 'selected' : '') + '>Blacklist IP</option>'
      + '<option value="unblacklist" ' + (defaultAction === 'unblacklist' ? 'selected' : '') + '>Unblacklist IP</option>'
      + '<option value="suspend" ' + (defaultAction === 'suspend' ? 'selected' : '') + '>Suspend IP</option>'
      + '<option value="unsuspend" ' + (defaultAction === 'unsuspend' ? 'selected' : '') + '>Unsuspend IP</option>'
      + '</select>'
      + '<label class="muted">Target IP</label>'
      + '<input id="qaIp" class="input" placeholder="1.2.3.4" value="' + esc(defaultIp || '') + '">'
      + '<label class="muted">Reason (for suspend)</label>'
      + '<input id="qaReason" class="input" placeholder="Abuse pattern detected" value="Admin action">'
      + '<div class="top-actions" style="margin-top:4px"><button id="qaSubmit" class="btn">Confirm</button><button id="qaCancel" class="btn secondary">Cancel</button></div>'
    );

    const submit = document.getElementById('qaSubmit');
    const cancel = document.getElementById('qaCancel');
    if (cancel) cancel.onclick = closeModal;
    if (submit) {
      submit.onclick = async function(){
        try {
          submit.disabled = true;
          const action = (document.getElementById('qaAction') || {}).value || 'blacklist';
          const ip = (document.getElementById('qaIp') || {}).value || '';
          const reason = (document.getElementById('qaReason') || {}).value || 'Admin action';
          await submitQuickAction({ action: action, ip: ip, reason: reason });
          closeModal();
          toast('Action completed successfully', 'ok');
          await renderDashboard();
        } catch (e) {
          toast((e && e.message) || 'Action failed', 'error');
        } finally {
          submit.disabled = false;
        }
      };
    }
  }

  function bindStaticActions(stats){
    const tabBtns = app.querySelectorAll('[data-tab]');
    tabBtns.forEach(function(btn){
      btn.addEventListener('click', function(){
        activeTab = String(btn.getAttribute('data-tab') || 'overview');
        renderDashboard(stats);
      });
    });

    const refresh = document.getElementById('refreshBtn');
    if (refresh) refresh.onclick = function(){ renderDashboard(); };

    const logout = document.getElementById('logoutBtn');
    if (logout) logout.onclick = async function(){
      try { await fetch('/__shield/admin/logout', { method: 'POST' }); } catch {}
      clearToken();
      renderLogin();
    };

    const quick = document.getElementById('quickActionBtn');
    if (quick) quick.onclick = function(){ openQuickActionModal('blacklist', ''); };

    const manageIpBtns = app.querySelectorAll('[data-manage-ip]');
    manageIpBtns.forEach(function(btn){
      btn.addEventListener('click', function(){
        openQuickActionModal('blacklist', String(btn.getAttribute('data-manage-ip') || ''));
      });
    });

    const quickBtns = app.querySelectorAll('[data-quick-action]');
    quickBtns.forEach(function(btn){
      btn.addEventListener('click', function(){
        openQuickActionModal(String(btn.getAttribute('data-quick-action') || 'blacklist'), '');
      });
    });

    const policyToggles = app.querySelectorAll('.policy-toggle');
    policyToggles.forEach(function(el){
      el.addEventListener('change', async function(){
        const key = String(el.getAttribute('data-key') || '');
        const checked = !!el.checked;
        try {
          const r = await api('/__shield/admin/protection', { method: 'POST', body: JSON.stringify({ updates: { [key]: checked } }) });
          runtimePolicy = r.policy || runtimePolicy;
          toast('Policy updated: ' + key, 'ok');
        } catch (e) {
          el.checked = !checked;
          toast((e && e.message) || 'Failed to update policy', 'error');
        }
      });
    });
  }

  async function loadPolicyIfNeeded(){
    if (activeTab !== 'settings') return;
    if (runtimePolicy) return;
    try {
      const data = await api('/__shield/admin/protection');
      runtimePolicy = data.policy || {};
    } catch (e) {
      toast('Could not load policy', 'error');
      runtimePolicy = {};
    }
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
      return renderLogin((e && e.message) || 'Failed to load dashboard');
    }

    await loadPolicyIfNeeded();

    let content = '';
    if (activeTab === 'overview') content = overviewTab(stats);
    else if (activeTab === 'threats') content = threatsTab(stats);
    else if (activeTab === 'traffic') content = trafficTab(stats);
    else if (activeTab === 'topips') content = topIpsTab(stats);
    else if (activeTab === 'profile') content = profileTab(stats);
    else if (activeTab === 'settings') content = settingsTab(runtimePolicy || {});
    else content = overviewTab(stats);

    app.innerHTML = '<div class="shell">'
      + rail()
      + sidebar()
      + '<main class="main"><div class="wrap">'
      + topBar()
      + '<div class="top-actions" style="margin-bottom:12px">'
      + '<button id="refreshBtn" class="btn">Refresh</button>'
      + '<button id="quickActionBtn" class="btn secondary">Quick Action</button>'
      + '<button id="logoutBtn" class="btn secondary">Logout</button>'
      + '</div>'
      + content
      + '</div></main>'
      + '</div>'
      + '<div id="modalBackdrop" class="modal-backdrop"><div class="modal"><div class="modal-head"><div class="modal-title">Shield Action</div><button id="modalClose" class="icon-x">✕</button></div><div id="modalBody" class="modal-body"></div></div></div>'
      + '<div id="toast" class="toast"></div>';

    bindStaticActions(stats);

    if (document.getElementById('bpChart')) {
      renderLine(stats);
    } else if (chart) {
      chart.destroy();
      chart = null;
    }
  }

  window.addEventListener('error', function(e){
    const msg = (e && (e.message || (e.error && e.error.message))) || 'Script error';
    renderFatal(msg);
  });

  try {
    renderDashboard(INITIAL_STATS || null);
    setInterval(function(){ renderDashboard(); }, 5000);
  } catch (e) {
    renderFatal((e && e.message) || 'Initialization failed');
  }
})();
</script>
</body>
</html>`;
}
