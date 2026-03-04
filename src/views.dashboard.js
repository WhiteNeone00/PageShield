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
  return `<div class="wrap" id="server-dashboard">
    <div class="top"><div><div class="title">Ryzeon Shield Live Dashboard</div><div class="muted">Host: ${safeHost} • Session active</div></div><div><button id="refreshBtn" class="btn">Refresh</button> <button id="logoutBtn" class="btn">Logout</button></div></div>
    <div class="grid">
      <section class="card kpi"><div class="sub">Live requests/sec</div><div class="val">${reqps}</div><div class="sub">Last minute total: ${reqpm}</div></section>
      <section class="card kpi"><div class="sub">Blocked (24h)</div><div class="val" style="color:var(--bad)">${blocked24}</div></section>
      <section class="card kpi"><div class="sub">Passed (24h)</div><div class="val" style="color:var(--ok)">${passed24}</div></section>
      <section class="card kpi"><div class="sub">Top IPs</div><div class="sub">${topIps.length}</div></section>
      <section class="card full"><div class="sub">Top Attacking IPs</div><div class="list" style="margin-top:8px">${topIps.length ? topIps.map(r => `<div class="row"><span>${escapeHtml(r.ip || 'N/A')}</span><span>${Number(r.count || 0)} hits</span></div>`).join('') : '<div class="muted">No recent attack data.</div>'}</div></section>
    </div>
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
    .wrap{max-width:1200px;margin:0 auto;padding:20px}
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
    canvas{width:100%;height:280px}
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

  async function renderDashboard(){
    let stats;
    try {
      stats = await api('/__shield/admin/dashboard');
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

    app.innerHTML = '<div class="wrap">'
      + '<div class="top"><div><div class="title">Ryzeon Shield Live Dashboard</div><div class="muted">Host: ' + SAFE_HOST + ' • Auto-refresh every 5s</div></div><div><button id="refreshBtn" class="btn">Refresh</button> <button id="logoutBtn" class="btn">Logout</button></div></div>'
      + '<div class="grid">'
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
      + '</div></div>';

    document.getElementById('refreshBtn').onclick = renderDashboard;
    document.getElementById('logoutBtn').onclick = async () => {
      try { await fetch('/__shield/admin/logout', { method: 'POST' }); } catch {}
      clearToken();
      renderLogin();
    };
    renderLine(stats);
  }

  try {
    if (INITIAL_STATS && document.getElementById('server-dashboard')) {
      document.getElementById('refreshBtn')?.addEventListener('click', renderDashboard);
      document.getElementById('logoutBtn')?.addEventListener('click', async () => {
        try { await fetch('/__shield/admin/logout', { method: 'POST' }); } catch {}
        clearToken();
        renderLogin();
      });
    } else {
      renderDashboard();
    }

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
