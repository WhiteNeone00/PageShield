function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function htmlShieldStats(host, initialStats = null) {
  const safeHost = escapeHtml(host || 'N/A');
  const initialStatsJson = JSON.stringify(initialStats || null);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Shield Control Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@500;700;800&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #f7f2e8;
      --bg-soft: #efe5d5;
      --ink: #1e293b;
      --ink-soft: #5b6470;
      --line: #dccdb8;
      --surface: rgba(255, 255, 255, 0.84);
      --surface-strong: #fffdf8;
      --brand: #0f766e;
      --brand-strong: #0e7490;
      --accent: #db7c31;
      --ok: #15803d;
      --warn: #b45309;
      --bad: #b91c1c;
      --radius-lg: 20px;
      --radius-md: 14px;
      --radius-sm: 10px;
      --shadow: 0 20px 44px rgba(72, 49, 19, 0.11);
      --shadow-soft: 0 10px 24px rgba(72, 49, 19, 0.08);
    }

    * {
      box-sizing: border-box;
    }

    html,
    body {
      height: 100%;
    }

    body {
      margin: 0;
      color: var(--ink);
      font-family: 'Manrope', 'Segoe UI', sans-serif;
      background:
        radial-gradient(840px 520px at -14% -20%, rgba(14, 116, 144, 0.18), transparent 60%),
        radial-gradient(820px 520px at 112% 126%, rgba(219, 124, 49, 0.15), transparent 60%),
        linear-gradient(170deg, var(--bg) 0%, var(--bg-soft) 100%);
      overflow-x: hidden;
    }

    .atmo {
      position: fixed;
      z-index: 0;
      pointer-events: none;
      border-radius: 999px;
      filter: blur(2px);
      opacity: 0.6;
    }

    .atmo.a {
      width: 420px;
      height: 420px;
      top: -160px;
      right: -120px;
      background: radial-gradient(circle, rgba(15, 118, 110, 0.3) 0%, rgba(15, 118, 110, 0) 72%);
    }

    .atmo.b {
      width: 520px;
      height: 520px;
      left: -180px;
      bottom: -200px;
      background: radial-gradient(circle, rgba(219, 124, 49, 0.24) 0%, rgba(219, 124, 49, 0) 70%);
    }

    .app-root {
      position: relative;
      z-index: 1;
      min-height: 100vh;
      padding: 18px;
    }

    .boot {
      max-width: 520px;
      margin: 20vh auto 0;
      padding: 22px;
      border-radius: var(--radius-lg);
      border: 1px solid var(--line);
      background: var(--surface);
      backdrop-filter: blur(8px);
      box-shadow: var(--shadow);
      font-weight: 700;
      letter-spacing: 0.2px;
      color: var(--ink-soft);
      text-align: center;
      animation: rise 0.45s ease;
    }

    .login-shell {
      min-height: calc(100vh - 36px);
      display: grid;
      place-items: center;
      animation: rise 0.42s ease;
    }

    .login-card {
      width: min(520px, 100%);
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 26px;
      padding: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(10px);
    }

    .login-kicker {
      font-size: 0.76rem;
      font-weight: 700;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--brand-strong);
    }

    .login-title {
      margin-top: 10px;
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: clamp(1.7rem, 3.4vw, 2.4rem);
      line-height: 1.1;
      letter-spacing: 0.01em;
    }

    .host-label {
      margin-top: 12px;
      padding: 9px 11px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.72);
      color: var(--ink-soft);
      font-size: 0.86rem;
      word-break: break-all;
    }

    .field {
      width: 100%;
      border-radius: 12px;
      border: 1px solid #cfbea8;
      background: #fffcf5;
      color: var(--ink);
      padding: 12px 13px;
      font: inherit;
      outline: none;
      transition: border-color 0.18s ease, box-shadow 0.18s ease;
    }

    .field:focus {
      border-color: rgba(14, 116, 144, 0.55);
      box-shadow: 0 0 0 3px rgba(14, 116, 144, 0.14);
    }

    .field-row {
      margin-top: 14px;
      display: grid;
      gap: 8px;
    }

    .label {
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      color: #6e6d68;
      font-weight: 700;
    }

    .btn {
      border: 1px solid transparent;
      border-radius: 12px;
      padding: 10px 13px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.16s ease, box-shadow 0.2s ease, filter 0.2s ease;
    }

    .btn:hover {
      transform: translateY(-1px);
      filter: brightness(1.02);
    }

    .btn:disabled {
      opacity: 0.65;
      cursor: not-allowed;
      transform: none;
      filter: none;
    }

    .btn.primary {
      color: #effdff;
      border-color: rgba(15, 118, 110, 0.44);
      background: linear-gradient(155deg, #0f766e 0%, #0e7490 100%);
      box-shadow: 0 8px 18px rgba(14, 116, 144, 0.24);
    }

    .btn.ghost {
      color: var(--ink);
      border-color: #ccbca6;
      background: #fffaf1;
    }

    .btn.warn {
      color: #7c2d12;
      border-color: rgba(180, 83, 9, 0.45);
      background: rgba(251, 191, 36, 0.22);
    }

    .btn.danger {
      color: #7f1d1d;
      border-color: rgba(185, 28, 28, 0.4);
      background: rgba(248, 113, 113, 0.16);
    }

    .btns {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .error {
      margin-top: 10px;
      min-height: 1.2rem;
      color: var(--bad);
      font-size: 0.86rem;
      font-weight: 600;
    }

    .shell {
      min-height: calc(100vh - 36px);
      display: grid;
      grid-template-columns: 278px 1fr;
      gap: 14px;
      animation: rise 0.35s ease;
    }

    .sidebar {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 18px 14px 14px;
      box-shadow: var(--shadow-soft);
      backdrop-filter: blur(8px);
      display: flex;
      flex-direction: column;
      min-height: 0;
    }

    .brand-kicker {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.19em;
      color: var(--brand-strong);
      font-weight: 800;
    }

    .brand {
      margin-top: 8px;
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: 1.95rem;
      line-height: 1;
      letter-spacing: 0.02em;
    }

    .brand-sub {
      margin-top: 6px;
      color: var(--ink-soft);
      font-size: 0.9rem;
    }

    .side-host {
      margin-top: 14px;
      padding: 10px;
      border: 1px dashed #cbbba4;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.72);
      font-size: 0.8rem;
      color: var(--ink-soft);
      word-break: break-all;
    }

    .menu {
      margin-top: 14px;
      display: grid;
      gap: 8px;
    }

    .menu-btn {
      border: 1px solid transparent;
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.58);
      color: var(--ink);
      text-align: left;
      padding: 10px 11px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .menu-btn:hover {
      border-color: rgba(15, 118, 110, 0.32);
      transform: translateX(2px);
    }

    .menu-btn.active {
      color: #f2ffff;
      background: linear-gradient(145deg, rgba(15, 118, 110, 0.92), rgba(14, 116, 144, 0.92));
      border-color: rgba(15, 118, 110, 0.44);
      box-shadow: 0 10px 20px rgba(14, 116, 144, 0.22);
    }

    .side-foot {
      margin-top: auto;
      font-size: 0.79rem;
      color: #6c695f;
      border-top: 1px solid var(--line);
      padding-top: 10px;
    }

    .workspace {
      min-width: 0;
      display: grid;
      grid-template-rows: auto 1fr;
      gap: 10px;
    }

    .toolbar {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 10px;
      box-shadow: var(--shadow-soft);
      display: flex;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar-left {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }

    .chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid #cdbda7;
      border-radius: 999px;
      background: #fffaf1;
      padding: 7px 12px;
      font-size: 0.82rem;
      font-weight: 700;
      color: #445162;
      max-width: 100%;
    }

    .chip .dot {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: #16a34a;
      box-shadow: 0 0 0 5px rgba(22, 163, 74, 0.16);
      flex: 0 0 auto;
    }

    .toolbar-right {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .content {
      min-width: 0;
      display: block;
    }

    .content-pane {
      animation: panel 0.26s ease both;
    }

    .hero {
      margin-bottom: 10px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px;
      box-shadow: var(--shadow-soft);
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
    }

    .hero h1 {
      margin: 0;
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: clamp(1.45rem, 2.5vw, 2rem);
      line-height: 1.1;
    }

    .hero p {
      margin: 5px 0 0;
      color: var(--ink-soft);
      font-size: 0.9rem;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 10px;
    }

    .metric {
      grid-column: span 3;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 15px;
      padding: 12px;
      box-shadow: var(--shadow-soft);
      position: relative;
      overflow: hidden;
    }

    .metric::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(130deg, rgba(255, 255, 255, 0.38), rgba(255, 255, 255, 0));
      pointer-events: none;
    }

    .metric .k {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #626f7d;
      font-weight: 800;
    }

    .metric .v {
      margin-top: 6px;
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: 1.7rem;
      line-height: 1;
    }

    .metric .s {
      margin-top: 6px;
      color: var(--ink-soft);
      font-size: 0.83rem;
      font-weight: 600;
    }

    .metric.ok .v { color: var(--ok); }
    .metric.warn .v { color: var(--warn); }
    .metric.bad .v { color: var(--bad); }

    .grid-two {
      margin-top: 10px;
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 10px;
    }

    .panel {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 12px;
      box-shadow: var(--shadow-soft);
      min-width: 0;
    }

    .panel-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      margin-bottom: 10px;
      flex-wrap: wrap;
    }

    .panel-title {
      margin: 0;
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: 1.15rem;
      line-height: 1.12;
    }

    .panel-sub {
      margin: 3px 0 0;
      color: var(--ink-soft);
      font-size: 0.84rem;
    }

    .mini-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }

    .mini {
      border: 1px solid #d8c9b4;
      border-radius: 12px;
      padding: 10px;
      background: rgba(255, 255, 255, 0.72);
      min-width: 0;
    }

    .mini .k {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #646b72;
      font-weight: 700;
    }

    .mini .v {
      margin-top: 5px;
      font-size: 1.07rem;
      font-weight: 800;
      word-break: break-word;
    }

    .list {
      display: grid;
      gap: 8px;
    }

    .row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      font-size: 0.9rem;
      min-width: 0;
    }

    .row > span {
      min-width: 0;
      word-break: break-word;
    }

    .bar {
      margin-top: 5px;
      width: 100%;
      height: 7px;
      border-radius: 999px;
      background: #efe2d1;
      overflow: hidden;
    }

    .bar span {
      display: block;
      height: 100%;
      background: linear-gradient(90deg, #0f766e, #0ea5a4);
    }

    .heat {
      margin-top: 8px;
      display: grid;
      grid-template-columns: repeat(24, minmax(0, 1fr));
      gap: 4px;
    }

    .cell {
      height: 17px;
      border-radius: 5px;
      border: 1px solid rgba(171, 145, 112, 0.18);
    }

    .legend {
      margin-top: 6px;
      font-size: 0.75rem;
      color: #6b6f76;
      display: flex;
      justify-content: space-between;
    }

    .table {
      display: grid;
      gap: 8px;
    }

    .table-row {
      display: grid;
      grid-template-columns: minmax(120px, 1fr) auto auto;
      gap: 8px;
      align-items: center;
      border: 1px solid #d8c9b4;
      border-radius: 12px;
      background: rgba(255, 255, 255, 0.74);
      padding: 9px;
    }

    .table-row .mono {
      font-family: 'ui-monospace', SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
      font-size: 0.84rem;
      color: #0f172a;
      word-break: break-all;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 0.74rem;
      font-weight: 800;
      border: 1px solid #d1c0a8;
      background: rgba(255, 255, 255, 0.64);
      color: #4a5563;
      white-space: nowrap;
    }

    .badge.good {
      color: #166534;
      border-color: rgba(21, 128, 61, 0.36);
      background: rgba(34, 197, 94, 0.16);
    }

    .badge.off {
      color: #7f1d1d;
      border-color: rgba(185, 28, 28, 0.36);
      background: rgba(248, 113, 113, 0.16);
    }

    .site-grid {
      display: grid;
      gap: 8px;
    }

    .site-card {
      border: 1px solid #d8c9b4;
      border-radius: 14px;
      padding: 10px;
      background: rgba(255, 255, 255, 0.72);
    }

    .site-card .domain {
      font-weight: 800;
      letter-spacing: 0.01em;
      word-break: break-all;
    }

    .site-card .meta {
      margin-top: 6px;
      font-size: 0.82rem;
      color: #5f6774;
      word-break: break-word;
    }

    .switch-list {
      display: grid;
      gap: 8px;
      margin-top: 8px;
    }

    .switch {
      border: 1px solid #d9c9b5;
      border-radius: 12px;
      padding: 10px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      background: rgba(255, 255, 255, 0.73);
    }

    .switch .name {
      font-weight: 700;
      color: #223042;
    }

    .switch .desc {
      margin-top: 3px;
      font-size: 0.81rem;
      color: #636c77;
    }

    .switch input {
      width: 20px;
      height: 20px;
      accent-color: #0f766e;
      cursor: pointer;
      margin: 0;
    }

    .danger-zone {
      border-color: rgba(185, 28, 28, 0.28);
      background: rgba(255, 228, 228, 0.64);
    }

    .muted {
      color: var(--ink-soft);
    }

    .empty {
      font-size: 0.88rem;
      color: #66717f;
      padding: 8px;
      border: 1px dashed #d4c6b3;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.62);
    }

    .chart-wrap {
      position: relative;
      width: 100%;
      height: 300px;
    }

    canvas {
      width: 100%;
      height: 100%;
    }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      z-index: 90;
      padding: 16px;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(32, 28, 20, 0.45);
      backdrop-filter: blur(2px);
    }

    .modal-backdrop.show {
      display: flex;
      animation: fade 0.2s ease;
    }

    .modal {
      width: min(620px, 100%);
      border-radius: 20px;
      border: 1px solid #d5c6b0;
      background: #fffdf9;
      box-shadow: var(--shadow);
      overflow: hidden;
      animation: rise 0.24s ease;
    }

    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 14px;
      border-bottom: 1px solid #dfd0bb;
      background: linear-gradient(140deg, rgba(15, 118, 110, 0.11), rgba(14, 116, 144, 0.09));
    }

    .modal-title {
      font-family: 'Bricolage Grotesque', sans-serif;
      font-size: 1.18rem;
    }

    .icon-btn {
      border: 1px solid #d2c1ab;
      background: #fff7ea;
      width: 34px;
      height: 34px;
      border-radius: 10px;
      cursor: pointer;
      font-size: 1rem;
      color: #494640;
    }

    .modal-body {
      padding: 14px;
      display: grid;
      gap: 9px;
    }

    .toast {
      position: fixed;
      z-index: 95;
      right: 16px;
      bottom: 16px;
      min-width: 240px;
      max-width: 420px;
      border-radius: 12px;
      border: 1px solid #d8c8b3;
      background: rgba(255, 254, 250, 0.96);
      box-shadow: var(--shadow-soft);
      padding: 10px 12px;
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: all 0.2s ease;
      color: #2f3a4a;
      font-weight: 700;
    }

    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }

    .toast.ok {
      border-color: rgba(21, 128, 61, 0.38);
      background: rgba(240, 253, 244, 0.96);
      color: #166534;
    }

    .toast.error {
      border-color: rgba(185, 28, 28, 0.4);
      background: rgba(254, 242, 242, 0.96);
      color: #991b1b;
    }

    @keyframes panel {
      from {
        opacity: 0.36;
        transform: translateY(7px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes rise {
      from {
        opacity: 0;
        transform: translateY(10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    @keyframes fade {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    @media (max-width: 1180px) {
      .metric { grid-column: span 6; }
      .grid-two { grid-template-columns: 1fr; }
      .table-row { grid-template-columns: 1fr; }
    }

    @media (max-width: 980px) {
      .app-root { padding: 12px; }
      .shell {
        grid-template-columns: 1fr;
        min-height: calc(100vh - 24px);
      }
      .sidebar {
        position: sticky;
        top: 12px;
        z-index: 20;
      }
      .menu {
        grid-template-columns: repeat(3, minmax(0, 1fr));
      }
      .menu-btn {
        text-align: center;
        padding: 9px 8px;
      }
      .brand,
      .brand-sub,
      .side-host,
      .side-foot {
        display: none;
      }
    }

    @media (max-width: 680px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metric { grid-column: span 1; }
      .mini-grid { grid-template-columns: 1fr; }
      .toolbar {
        border-radius: 14px;
      }
      .hero {
        border-radius: 14px;
      }
      .btns,
      .toolbar-right {
        width: 100%;
      }
      .toolbar-right .btn,
      .btns .btn {
        flex: 1;
      }
      .menu {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
</head>
<body>
  <div class="atmo a"></div>
  <div class="atmo b"></div>
  <div id="app" class="app-root">
    <div class="boot">Loading Shield control center...</div>
  </div>

  <div id="modalBackdrop" class="modal-backdrop">
    <div class="modal">
      <div class="modal-head">
        <div id="modalTitle" class="modal-title">Action</div>
        <button id="modalClose" class="icon-btn" type="button">X</button>
      </div>
      <div id="modalBody" class="modal-body"></div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
  (() => {
    const SAFE_HOST = ${JSON.stringify(safeHost)};
    const INITIAL_STATS = ${initialStatsJson};
    const TOKEN_KEY = 'shield_admin_jwt';

    const app = document.getElementById('app');
    const modalBackdrop = document.getElementById('modalBackdrop');
    const modalTitle = document.getElementById('modalTitle');
    const modalBody = document.getElementById('modalBody');
    const modalClose = document.getElementById('modalClose');
    const toastEl = document.getElementById('toast');

    let activeTab = 'overview';
    let runtimePolicy = null;
    let sitesCache = null;
    let chart = null;
    let pollTimer = null;
    let toastTimer = null;
    let rendering = false;

    function esc(v) {
      return String(v == null ? '' : v).replace(/[&<>"']/g, function (m) {
        return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m];
      });
    }

    function flag(code) {
      const value = String(code || '').toUpperCase();
      if (!/^[A-Z]{2}$/.test(value)) return 'GL';
      return value;
    }

    function getToken() {
      try {
        return localStorage.getItem(TOKEN_KEY) || '';
      } catch {
        return '';
      }
    }

    function setToken(v) {
      try {
        localStorage.setItem(TOKEN_KEY, v || '');
      } catch {}
    }

    function clearToken() {
      try {
        localStorage.removeItem(TOKEN_KEY);
      } catch {}
    }

    async function api(path, opts = {}) {
      const token = getToken();
      const headers = { 'content-type': 'application/json' };
      const extraHeaders = opts.headers && typeof opts.headers === 'object' ? opts.headers : {};
      for (const key of Object.keys(extraHeaders)) headers[key] = extraHeaders[key];
      if (token) headers.authorization = 'Bearer ' + token;

      const response = await fetch(path, { ...opts, headers: headers });
      const text = await response.text();
      let data = {};
      try {
        data = JSON.parse(text || '{}');
      } catch {
        data = {};
      }

      if (!response.ok) {
        const err = new Error(data.error || ('HTTP ' + response.status));
        err.status = response.status;
        throw err;
      }
      return data;
    }

    function showToast(message, type) {
      if (!toastEl) return;
      if (toastTimer) clearTimeout(toastTimer);
      toastEl.className = 'toast show ' + (type === 'error' ? 'error' : 'ok');
      toastEl.textContent = message || '';
      toastTimer = setTimeout(function () {
        toastEl.className = 'toast';
      }, 2400);
    }

    function openModal(title, html) {
      if (!modalBackdrop || !modalBody || !modalTitle) return;
      modalTitle.textContent = title || 'Action';
      modalBody.innerHTML = html || '';
      modalBackdrop.classList.add('show');
    }

    function closeModal() {
      if (!modalBackdrop) return;
      modalBackdrop.classList.remove('show');
      if (modalBody) modalBody.innerHTML = '';
    }

    if (modalClose) {
      modalClose.addEventListener('click', closeModal);
    }
    if (modalBackdrop) {
      modalBackdrop.addEventListener('click', function (ev) {
        if (ev.target === modalBackdrop) closeModal();
      });
    }
    window.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') closeModal();
    });

    function buildHeatmap(hours) {
      const values = Array.isArray(hours) ? hours : [];
      const max = Math.max(1, ...values.map(function (x) { return Number(x.blocked || 0); }));
      return '<div class="heat">' + values.map(function (item) {
        const count = Number(item.blocked || 0);
        const alpha = Math.max(0.1, count / max);
        const title = esc((item.hour || '00') + ':00 blocked=' + count);
        return '<div class="cell" title="' + title + '" style="background: rgba(185, 28, 28, ' + alpha.toFixed(3) + ')"></div>';
      }).join('') + '</div><div class="legend"><span>00:00</span><span>23:00</span></div>';
    }

    function sidebar() {
      const tabs = [
        ['overview', 'Overview'],
        ['threats', 'Threat Ops'],
        ['traffic', 'Traffic'],
        ['topips', 'Top IPs'],
        ['sites', 'Sites'],
        ['settings', 'Policy'],
        ['profile', 'Profile'],
      ];

      return '<aside class="sidebar">'
        + '<div class="brand-kicker">Ryzeon Shield</div>'
        + '<div class="brand">Control</div>'
        + '<div class="brand-sub">Security operations dashboard</div>'
        + '<div class="side-host">Host: ' + esc(SAFE_HOST) + '</div>'
        + '<nav class="menu">'
        + tabs.map(function (tab) {
          return '<button class="menu-btn' + (activeTab === tab[0] ? ' active' : '') + '" data-tab="' + tab[0] + '">' + tab[1] + '</button>';
        }).join('')
        + '</nav>'
        + '<div class="side-foot">Shield v3 · Smooth panel rebuild</div>'
        + '</aside>';
    }

    function toolbar(stats) {
      const reqps = Number(stats && stats.live ? stats.live.requestsPerSecond : 0).toFixed(2);
      return '<header class="toolbar">'
        + '<div class="toolbar-left">'
        + '<div class="chip"><span class="dot"></span><span>Live ' + reqps + ' req/s</span></div>'
        + '<div class="chip"><span>Host ' + esc(SAFE_HOST) + '</span></div>'
        + '</div>'
        + '<div class="toolbar-right">'
        + '<button id="refreshBtn" class="btn ghost" type="button">Refresh</button>'
        + '<button id="quickActionBtn" class="btn warn" type="button">Quick Action</button>'
        + '<button id="logoutBtn" class="btn ghost" type="button">Logout</button>'
        + '</div>'
        + '</header>';
    }

    function overviewTab(stats) {
      const requestsMinute = Number(stats && stats.live ? stats.live.requestsLastMinute : 0);
      const reqps = Number(stats && stats.live ? stats.live.requestsPerSecond : 0).toFixed(2);
      const blocked = Number(stats && stats.kpi ? stats.kpi.blocked24h : 0);
      const passed = Number(stats && stats.kpi ? stats.kpi.passed24h : 0);
      const attackIps = Number(stats && stats.kpi ? stats.kpi.uniqueAttackIps24h : 0);
      const countries = Number(stats && stats.kpi ? stats.kpi.activeCountries24h : 0);
      const ratio = blocked + passed > 0 ? ((blocked / (blocked + passed)) * 100).toFixed(1) : '0.0';
      const topCountries = (Array.isArray(stats && stats.countries ? stats.countries : []) ? stats.countries : []).slice(0, 8);
      const topIps = (Array.isArray(stats && stats.topIps ? stats.topIps : []) ? stats.topIps : []).slice(0, 8);
      const countryMax = Math.max(1, ...topCountries.map(function (row) { return Number(row.count || 0); }));

      return '<section class="content-pane">'
        + '<div class="hero">'
        + '<div><h1>Shield operations at a glance</h1><p>Live threat pressure, enforcement posture, and traffic quality in one board.</p></div>'
        + '<div class="badge">Threat ratio ' + ratio + '%</div>'
        + '</div>'
        + '<div class="metrics">'
        + '<article class="metric"><div class="k">Requests per second</div><div class="v">' + reqps + '</div><div class="s">Last minute ' + requestsMinute + '</div></article>'
        + '<article class="metric bad"><div class="k">Blocked 24h</div><div class="v">' + blocked + '</div><div class="s">Challenged or denied requests</div></article>'
        + '<article class="metric ok"><div class="k">Passed 24h</div><div class="v">' + passed + '</div><div class="s">Validated clean traffic</div></article>'
        + '<article class="metric warn"><div class="k">Unique attack IPs</div><div class="v">' + attackIps + '</div><div class="s">Countries involved ' + countries + '</div></article>'
        + '</div>'
        + '<div class="grid-two">'
        + '<article class="panel"><div class="panel-head"><div><h2 class="panel-title">Threat pressure heatmap</h2><p class="panel-sub">Hourly blocked activity during the last 24h</p></div></div>'
        + buildHeatmap(Array.isArray(stats && stats.heatmap ? stats.heatmap : []) ? stats.heatmap : [])
        + '</article>'
        + '<article class="panel"><div class="panel-head"><div><h2 class="panel-title">Top countries</h2><p class="panel-sub">Where blocked traffic is coming from</p></div></div>'
        + '<div class="list">'
        + (topCountries.length ? topCountries.map(function (row) {
          const count = Number(row.count || 0);
          const width = Math.max(5, Math.round((count / countryMax) * 100));
          return '<div>'
            + '<div class="row"><span>' + esc(flag(row.country)) + '</span><span>' + count + '</span></div>'
            + '<div class="bar"><span style="width:' + width + '%"></span></div>'
            + '</div>';
        }).join('') : '<div class="empty">No country-level threat data yet.</div>')
        + '</div>'
        + '</article>'
        + '</div>'
        + '<article class="panel" style="margin-top:10px"><div class="panel-head"><div><h2 class="panel-title">Blocked vs passed trend</h2><p class="panel-sub">Traffic quality curve for the last 24h</p></div></div><div class="chart-wrap"><canvas id="trafficChart"></canvas></div></article>'
        + '<article class="panel" style="margin-top:10px"><div class="panel-head"><div><h2 class="panel-title">Top attacking IPs</h2><p class="panel-sub">Fast moderation actions ready</p></div></div><div class="table">'
        + (topIps.length ? topIps.map(function (row) {
          return '<div class="table-row"><span class="mono">' + esc(row.ip || 'N/A') + '</span><span class="badge">' + Number(row.count || 0) + ' hits</span><button class="btn ghost" type="button" data-manage-ip="' + esc(row.ip || '') + '">Manage</button></div>';
        }).join('') : '<div class="empty">No attack leaders in the selected window.</div>')
        + '</div></article>'
        + '</section>';
    }

    function threatsTab(stats) {
      const topIps = (Array.isArray(stats && stats.topIps ? stats.topIps : []) ? stats.topIps : []).slice(0, 6);
      const blocked = Number(stats && stats.kpi ? stats.kpi.blocked24h : 0);
      const attackIps = Number(stats && stats.kpi ? stats.kpi.uniqueAttackIps24h : 0);
      const countries = Number(stats && stats.kpi ? stats.kpi.activeCountries24h : 0);

      return '<section class="content-pane">'
        + '<div class="hero"><div><h1>Threat operations</h1><p>Rapid response tools for active abuse and hostile traffic.</p></div></div>'
        + '<article class="panel">'
        + '<div class="panel-head"><div><h2 class="panel-title">Immediate actions</h2><p class="panel-sub">Use one modal for blacklisting, unblacklisting, suspend, or unsuspend.</p></div></div>'
        + '<div class="btns">'
        + '<button class="btn warn" type="button" data-quick-action="suspend">Suspend IP</button>'
        + '<button class="btn ghost" type="button" data-quick-action="unsuspend">Unsuspend IP</button>'
        + '<button class="btn danger" type="button" data-quick-action="blacklist">Blacklist IP</button>'
        + '<button class="btn primary" type="button" data-quick-action="unblacklist">Unblacklist IP</button>'
        + '</div>'
        + '</article>'
        + '<article class="panel" style="margin-top:10px">'
        + '<div class="panel-head"><div><h2 class="panel-title">24h threat snapshot</h2><p class="panel-sub">Current pressure and spread.</p></div></div>'
        + '<div class="mini-grid">'
        + '<div class="mini"><div class="k">Blocked requests</div><div class="v" style="color:#b91c1c">' + blocked + '</div></div>'
        + '<div class="mini"><div class="k">Unique attackers</div><div class="v">' + attackIps + '</div></div>'
        + '<div class="mini"><div class="k">Active countries</div><div class="v">' + countries + '</div></div>'
        + '</div>'
        + '</article>'
        + '<article class="panel" style="margin-top:10px">'
        + '<div class="panel-head"><div><h2 class="panel-title">Hot IP queue</h2><p class="panel-sub">Most aggressive addresses in this window.</p></div></div>'
        + '<div class="table">'
        + (topIps.length ? topIps.map(function (row) {
          return '<div class="table-row"><span class="mono">' + esc(row.ip || 'N/A') + '</span><span class="badge">' + Number(row.count || 0) + ' hits</span><button class="btn ghost" type="button" data-manage-ip="' + esc(row.ip || '') + '">Action</button></div>';
        }).join('') : '<div class="empty">No urgent IP actions right now.</div>')
        + '</div>'
        + '</article>'
        + '</section>';
    }

    function trafficTab(stats) {
      const hourly = Array.isArray(stats && stats.hourly ? stats.hourly : []) ? stats.hourly : [];
      const passed = hourly.reduce(function (sum, row) { return sum + Number(row.passed || 0); }, 0);
      const blocked = hourly.reduce(function (sum, row) { return sum + Number(row.blocked || 0); }, 0);
      const reqps = Number(stats && stats.live ? stats.live.requestsPerSecond : 0).toFixed(2);

      return '<section class="content-pane">'
        + '<div class="hero"><div><h1>Traffic quality</h1><p>Understand clean flow versus hostile flow over time.</p></div></div>'
        + '<article class="panel">'
        + '<div class="mini-grid">'
        + '<div class="mini"><div class="k">Total passed</div><div class="v" style="color:#15803d">' + passed + '</div></div>'
        + '<div class="mini"><div class="k">Total blocked</div><div class="v" style="color:#b91c1c">' + blocked + '</div></div>'
        + '<div class="mini"><div class="k">Live RPS</div><div class="v">' + reqps + '</div></div>'
        + '</div>'
        + '</article>'
        + '<article class="panel" style="margin-top:10px"><div class="panel-head"><div><h2 class="panel-title">24h throughput</h2><p class="panel-sub">Blocked versus passed requests by hour.</p></div></div><div class="chart-wrap"><canvas id="trafficChart"></canvas></div></article>'
        + '</section>';
    }

    function topIpsTab(stats) {
      const topIps = (Array.isArray(stats && stats.topIps ? stats.topIps : []) ? stats.topIps : []).slice(0, 24);
      return '<section class="content-pane">'
        + '<div class="hero"><div><h1>Top IP offenders</h1><p>Prioritize high-volume attackers with one-click actions.</p></div></div>'
        + '<article class="panel">'
        + '<div class="panel-head"><div><h2 class="panel-title">IP ranking</h2><p class="panel-sub">Sorted by blocked activity count.</p></div></div>'
        + '<div class="table">'
        + (topIps.length ? topIps.map(function (row, idx) {
          const ip = esc(row.ip || 'N/A');
          const count = Number(row.count || 0);
          return '<div class="table-row"><span class="mono">#' + (idx + 1) + ' ' + ip + '</span><span class="badge">' + count + ' hits</span><button class="btn ghost" type="button" data-manage-ip="' + ip + '">Manage</button></div>';
        }).join('') : '<div class="empty">No IP data available yet.</div>')
        + '</div>'
        + '</article>'
        + '</section>';
    }

    function sitesTab(sites) {
      const rows = Array.isArray(sites) ? sites : [];
      return '<section class="content-pane">'
        + '<div class="hero"><div><h1>Protected sites</h1><p>Manage domains reverse-proxied through Shield.</p></div><button id="addSiteBtn" class="btn primary" type="button">Add Domain</button></div>'
        + '<article class="panel">'
        + '<div class="panel-head"><div><h2 class="panel-title">Active tenant list</h2><p class="panel-sub">Enable, disable, or remove protected domains.</p></div></div>'
        + '<div class="site-grid">'
        + (rows.length ? rows.map(function (site) {
          const domain = esc(site.domain || 'N/A');
          const origin = esc(site.originUrl || 'N/A');
          const plan = esc(site.plan || 'free');
          const key = esc(site.apiKey || 'N/A');
          const active = !!site.active;
          return '<div class="site-card">'
            + '<div class="row"><span class="domain">' + domain + '</span><span class="badge ' + (active ? 'good' : 'off') + '">' + (active ? 'Active' : 'Disabled') + '</span></div>'
            + '<div class="meta">Origin: ' + origin + '</div>'
            + '<div class="meta">Plan: ' + plan + '</div>'
            + '<div class="meta">API Key: <span class="mono">' + key + '</span></div>'
            + '<div class="btns" style="margin-top:8px">'
            + '<button class="btn ghost" type="button" data-site-toggle="' + domain + '" data-site-active="' + (active ? '1' : '0') + '">' + (active ? 'Disable' : 'Enable') + '</button>'
            + '<button class="btn danger" type="button" data-site-remove="' + domain + '">Remove</button>'
            + '</div>'
            + '</div>';
        }).join('') : '<div class="empty">No protected sites yet. Add your first domain to start proxying through Shield.</div>')
        + '</div>'
        + '</article>'
        + '<article class="panel" style="margin-top:10px"><div class="panel-head"><div><h2 class="panel-title">Routing checklist</h2><p class="panel-sub">Keep onboarding steps visible for your team.</p></div></div>'
        + '<div class="list">'
        + '<div class="row"><span>1. Add domain with origin URL above.</span></div>'
        + '<div class="row"><span>2. Point DNS to your worker host: ' + esc(SAFE_HOST) + '.</span></div>'
        + '<div class="row"><span>3. Verify traffic appears in dashboard metrics.</span></div>'
        + '<div class="row"><span>4. Keep origin hidden and monitor threat ratio.</span></div>'
        + '</div></article>'
        + '</section>';
    }

    function settingsTab(policy) {
      const p = policy || {};
      const rows = [
        ['protectEnabled', 'Global protection', 'Master gate for all challenge and detection flows.', !!p.protectEnabled],
        ['rateLimitEnabled', 'Rate limiting', 'Apply request window controls before escalation.', !!p.rateLimitEnabled],
        ['attackBlockEnabled', 'Attack blocking', 'Auto-block requests classified as active attacks.', !!p.attackBlockEnabled],
        ['honeypotEnabled', 'Honeypot traps', 'Enable deceptive endpoint and form traps.', !!p.honeypotEnabled],
        ['aiCrawlerBlockEnabled', 'AI crawler block', 'Block or challenge known automated crawler signatures.', !!p.aiCrawlerBlockEnabled],
        ['ddosBlockEnabled', 'DDoS heuristics', 'Escalate large, coordinated flood patterns quickly.', !!p.ddosBlockEnabled],
        ['vpnBlockEnabled', 'VPN/proxy block', 'Apply VPN and anonymizer network restrictions.', !!p.vpnBlockEnabled],
      ];

      return '<section class="content-pane">'
        + '<div class="hero"><div><h1>Policy controls</h1><p>Adjust enforcement behavior in real time without redeploying.</p></div></div>'
        + '<article class="panel">'
        + '<div class="panel-head"><div><h2 class="panel-title">Live toggles</h2><p class="panel-sub">Changes are committed to Shield KV immediately.</p></div></div>'
        + '<div class="switch-list">'
        + rows.map(function (row) {
          return '<label class="switch"><div><div class="name">' + row[1] + '</div><div class="desc">' + row[2] + '</div></div><input class="policy-toggle" data-key="' + row[0] + '" type="checkbox" ' + (row[3] ? 'checked' : '') + '></label>';
        }).join('')
        + '</div>'
        + '</article>'
        + '<article class="panel danger-zone" style="margin-top:10px">'
        + '<div class="panel-head"><div><h2 class="panel-title">High impact actions</h2><p class="panel-sub">Fast path for emergency IP moderation.</p></div></div>'
        + '<div class="btns">'
        + '<button class="btn danger" type="button" data-quick-action="suspend">Suspend IP</button>'
        + '<button class="btn ghost" type="button" data-quick-action="unsuspend">Unsuspend IP</button>'
        + '</div>'
        + '</article>'
        + '</section>';
    }

    function profileTab(stats) {
      const ua = esc(navigator.userAgent || 'Unknown');
      const version = esc((stats && stats.version) || 'v3');
      return '<section class="content-pane">'
        + '<div class="hero"><div><h1>Session profile</h1><p>Operator context for this authenticated dashboard session.</p></div></div>'
        + '<article class="panel">'
        + '<div class="mini-grid">'
        + '<div class="mini"><div class="k">Role</div><div class="v">Shield Admin</div></div>'
        + '<div class="mini"><div class="k">Session state</div><div class="v">Active</div></div>'
        + '<div class="mini"><div class="k">Host</div><div class="v">' + esc(SAFE_HOST) + '</div></div>'
        + '</div>'
        + '</article>'
        + '<article class="panel" style="margin-top:10px">'
        + '<div class="panel-head"><div><h2 class="panel-title">Runtime details</h2><p class="panel-sub">Environment snapshot from browser context.</p></div><span class="badge">Shield ' + version + '</span></div>'
        + '<div class="empty" style="word-break:break-word">' + ua + '</div>'
        + '</article>'
        + '</section>';
    }

    function renderTab(stats) {
      if (activeTab === 'overview') return overviewTab(stats);
      if (activeTab === 'threats') return threatsTab(stats);
      if (activeTab === 'traffic') return trafficTab(stats);
      if (activeTab === 'topips') return topIpsTab(stats);
      if (activeTab === 'sites') return sitesTab(sitesCache || []);
      if (activeTab === 'settings') return settingsTab(runtimePolicy || {});
      if (activeTab === 'profile') return profileTab(stats);
      return overviewTab(stats);
    }

    function drawTrafficChart(stats) {
      const el = document.getElementById('trafficChart');
      if (!el) {
        if (chart) {
          chart.destroy();
          chart = null;
        }
        return;
      }
      if (typeof Chart === 'undefined') return;

      const hourly = Array.isArray(stats && stats.hourly ? stats.hourly : []) ? stats.hourly : [];
      const labels = hourly.map(function (row) { return String(row.hour || '00') + ':00'; });
      const blocked = hourly.map(function (row) { return Number(row.blocked || 0); });
      const passed = hourly.map(function (row) { return Number(row.passed || 0); });

      if (chart) chart.destroy();
      chart = new Chart(el, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'Blocked',
              data: blocked,
              borderColor: '#b91c1c',
              backgroundColor: 'rgba(185, 28, 28, 0.16)',
              fill: true,
              tension: 0.34,
              pointRadius: 0,
              borderWidth: 2,
            },
            {
              label: 'Passed',
              data: passed,
              borderColor: '#15803d',
              backgroundColor: 'rgba(21, 128, 61, 0.12)',
              fill: true,
              tension: 0.34,
              pointRadius: 0,
              borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { intersect: false, mode: 'index' },
          plugins: {
            legend: {
              labels: {
                color: '#4a5563',
                boxWidth: 12,
                boxHeight: 12,
              },
            },
          },
          scales: {
            x: {
              ticks: { color: '#66727f' },
              grid: { color: 'rgba(107, 114, 128, 0.18)' },
            },
            y: {
              beginAtZero: true,
              ticks: { color: '#66727f' },
              grid: { color: 'rgba(107, 114, 128, 0.18)' },
            },
          },
        },
      });
    }

    function renderLogin(error) {
      if (!app) return;
      app.innerHTML = '<div class="login-shell">'
        + '<section class="login-card">'
        + '<div class="login-kicker">Ryzeon</div>'
        + '<div class="login-title">Shield Admin Control Center</div>'
        + '<div class="host-label">Host: ' + esc(SAFE_HOST) + '</div>'
        + '<form id="loginForm">'
        + '<div class="field-row"><label class="label" for="adminPass">Password</label><input id="adminPass" class="field" type="password" autocomplete="current-password" placeholder="Enter admin password"></div>'
        + '<div class="btns" style="margin-top:14px"><button id="loginBtn" class="btn primary" type="submit">Enter Dashboard</button></div>'
        + '</form>'
        + '<div class="error" id="loginError">' + esc(error || '') + '</div>'
        + '</section>'
        + '</div>';

      const form = document.getElementById('loginForm');
      const button = document.getElementById('loginBtn');
      if (!form || !button) return;

      form.onsubmit = async function (ev) {
        ev.preventDefault();
        const passEl = document.getElementById('adminPass');
        const password = passEl ? String(passEl.value || '') : '';
        const errEl = document.getElementById('loginError');
        if (errEl) errEl.textContent = '';
        if (!password) {
          if (errEl) errEl.textContent = 'Password is required.';
          return;
        }

        button.disabled = true;
        try {
          const response = await fetch('/__shield/admin/login', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ password: password }),
          });
          let data = {};
          try {
            data = await response.json();
          } catch {
            data = {};
          }
          if (!response.ok || !data.token) {
            throw new Error(data.error || 'Login failed');
          }

          setToken(String(data.token));
          runtimePolicy = null;
          sitesCache = null;
          activeTab = 'overview';
          showToast('Login successful', 'ok');
          await renderDashboard();
          startPolling();
        } catch (err) {
          if (errEl) errEl.textContent = err && err.message ? err.message : 'Login failed';
        } finally {
          button.disabled = false;
        }
      };
    }

    async function runQuickAction(action, ip, reason) {
      const targetIp = String(ip || '').trim();
      if (!targetIp) throw new Error('IP is required');

      if (action === 'blacklist') {
        return api('/__shield/admin/blacklist/add', {
          method: 'POST',
          body: JSON.stringify({ ip: targetIp }),
        });
      }
      if (action === 'unblacklist') {
        return api('/__shield/admin/unblacklist', {
          method: 'POST',
          body: JSON.stringify({ ip: targetIp }),
        });
      }
      if (action === 'suspend') {
        return api('/__shield/admin/ip/suspend', {
          method: 'POST',
          body: JSON.stringify({
            ip: targetIp,
            reason: String(reason || 'Admin suspend'),
            permanent: true,
            durationSeconds: 3600,
          }),
        });
      }
      if (action === 'unsuspend') {
        return api('/__shield/admin/ip/unsuspend', {
          method: 'POST',
          body: JSON.stringify({ ip: targetIp }),
        });
      }
      throw new Error('Unsupported action');
    }

    function openQuickActionModal(defaultAction, defaultIp) {
      openModal('Quick IP Action',
        '<div class="muted">Apply a moderation command to a target IP address.</div>'
        + '<div class="field-row"><label class="label" for="qaAction">Action</label>'
        + '<select id="qaAction" class="field">'
        + '<option value="blacklist"' + (defaultAction === 'blacklist' ? ' selected' : '') + '>Blacklist IP</option>'
        + '<option value="unblacklist"' + (defaultAction === 'unblacklist' ? ' selected' : '') + '>Unblacklist IP</option>'
        + '<option value="suspend"' + (defaultAction === 'suspend' ? ' selected' : '') + '>Suspend IP</option>'
        + '<option value="unsuspend"' + (defaultAction === 'unsuspend' ? ' selected' : '') + '>Unsuspend IP</option>'
        + '</select></div>'
        + '<div class="field-row"><label class="label" for="qaIp">Target IP</label><input id="qaIp" class="field" placeholder="1.2.3.4" value="' + esc(defaultIp || '') + '"></div>'
        + '<div class="field-row"><label class="label" for="qaReason">Reason (suspend)</label><input id="qaReason" class="field" value="Admin action"></div>'
        + '<div class="btns" style="margin-top:6px"><button id="qaSubmit" class="btn primary" type="button">Run Action</button><button id="qaCancel" class="btn ghost" type="button">Cancel</button></div>'
      );

      const submit = document.getElementById('qaSubmit');
      const cancel = document.getElementById('qaCancel');
      if (cancel) cancel.onclick = closeModal;
      if (!submit) return;

      submit.onclick = async function () {
        const actionEl = document.getElementById('qaAction');
        const ipEl = document.getElementById('qaIp');
        const reasonEl = document.getElementById('qaReason');
        const action = actionEl ? String(actionEl.value || '') : 'blacklist';
        const ip = ipEl ? String(ipEl.value || '') : '';
        const reason = reasonEl ? String(reasonEl.value || '') : '';

        submit.disabled = true;
        try {
          await runQuickAction(action, ip, reason);
          closeModal();
          showToast('Action completed for ' + ip, 'ok');
          await renderDashboard();
        } catch (err) {
          showToast(err && err.message ? err.message : 'Action failed', 'error');
        } finally {
          submit.disabled = false;
        }
      };
    }

    function openAddSiteModal() {
      openModal('Add Protected Domain',
        '<div class="muted">Register a domain and origin server for Shield reverse proxy.</div>'
        + '<div class="field-row"><label class="label" for="siteDomain">Domain</label><input id="siteDomain" class="field" placeholder="app.example.com"></div>'
        + '<div class="field-row"><label class="label" for="siteOrigin">Origin URL</label><input id="siteOrigin" class="field" placeholder="https://origin.example.com"></div>'
        + '<div class="field-row"><label class="label" for="siteEmail">Owner email (optional)</label><input id="siteEmail" class="field" placeholder="admin@example.com"></div>'
        + '<div class="field-row"><label class="label" for="sitePlan">Plan</label><select id="sitePlan" class="field"><option value="free">Free</option><option value="pro">Pro</option><option value="enterprise">Enterprise</option></select></div>'
        + '<div class="btns" style="margin-top:6px"><button id="siteSubmit" class="btn primary" type="button">Add Domain</button><button id="siteCancel" class="btn ghost" type="button">Cancel</button></div>'
      );

      const submit = document.getElementById('siteSubmit');
      const cancel = document.getElementById('siteCancel');
      if (cancel) cancel.onclick = closeModal;
      if (!submit) return;

      submit.onclick = async function () {
        const domain = String((document.getElementById('siteDomain') || {}).value || '').trim();
        const originUrl = String((document.getElementById('siteOrigin') || {}).value || '').trim();
        const ownerEmail = String((document.getElementById('siteEmail') || {}).value || '').trim();
        const plan = String((document.getElementById('sitePlan') || {}).value || 'free').trim();

        if (!domain || !originUrl) {
          showToast('Domain and origin URL are required', 'error');
          return;
        }

        submit.disabled = true;
        try {
          await api('/__shield/admin/sites/add', {
            method: 'POST',
            body: JSON.stringify({ domain: domain, originUrl: originUrl, ownerEmail: ownerEmail, plan: plan }),
          });
          closeModal();
          sitesCache = null;
          showToast('Site added: ' + domain, 'ok');
          await renderDashboard();
        } catch (err) {
          showToast(err && err.message ? err.message : 'Failed to add site', 'error');
        } finally {
          submit.disabled = false;
        }
      };
    }

    function openRemoveSiteModal(domain) {
      const value = String(domain || '').trim();
      if (!value) return;
      openModal('Remove Protected Domain',
        '<div class="muted">Remove <strong>' + esc(value) + '</strong> from Shield routing?</div>'
        + '<div class="empty">This immediately stops proxying traffic for this domain.</div>'
        + '<div class="btns" style="margin-top:6px"><button id="removeSiteConfirm" class="btn danger" type="button">Remove</button><button id="removeSiteCancel" class="btn ghost" type="button">Cancel</button></div>'
      );

      const confirm = document.getElementById('removeSiteConfirm');
      const cancel = document.getElementById('removeSiteCancel');
      if (cancel) cancel.onclick = closeModal;
      if (!confirm) return;

      confirm.onclick = async function () {
        confirm.disabled = true;
        try {
          await api('/__shield/admin/sites/remove', {
            method: 'POST',
            body: JSON.stringify({ domain: value }),
          });
          closeModal();
          sitesCache = null;
          showToast('Site removed: ' + value, 'ok');
          await renderDashboard();
        } catch (err) {
          showToast(err && err.message ? err.message : 'Failed to remove site', 'error');
        } finally {
          confirm.disabled = false;
        }
      };
    }

    async function loadPolicyIfNeeded() {
      if (activeTab !== 'settings') return;
      if (runtimePolicy) return;
      try {
        const data = await api('/__shield/admin/protection');
        runtimePolicy = data.policy || {};
      } catch (err) {
        runtimePolicy = {};
        showToast('Policy load failed', 'error');
      }
    }

    async function loadSitesIfNeeded() {
      if (activeTab !== 'sites') return;
      if (sitesCache) return;
      try {
        const data = await api('/__shield/admin/sites');
        sitesCache = Array.isArray(data.sites) ? data.sites : [];
      } catch (err) {
        sitesCache = [];
        showToast('Site list load failed', 'error');
      }
    }

    function bindEvents(stats) {
      const tabButtons = app.querySelectorAll('[data-tab]');
      tabButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          activeTab = String(btn.getAttribute('data-tab') || 'overview');
          renderDashboard(stats);
        });
      });

      const refreshBtn = document.getElementById('refreshBtn');
      if (refreshBtn) {
        refreshBtn.onclick = function () {
          renderDashboard();
        };
      }

      const quickActionBtn = document.getElementById('quickActionBtn');
      if (quickActionBtn) {
        quickActionBtn.onclick = function () {
          openQuickActionModal('blacklist', '');
        };
      }

      const logoutBtn = document.getElementById('logoutBtn');
      if (logoutBtn) {
        logoutBtn.onclick = async function () {
          try {
            await fetch('/__shield/admin/logout', { method: 'POST' });
          } catch {}
          clearToken();
          runtimePolicy = null;
          sitesCache = null;
          activeTab = 'overview';
          renderLogin();
        };
      }

      const quickButtons = app.querySelectorAll('[data-quick-action]');
      quickButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          const action = String(btn.getAttribute('data-quick-action') || 'blacklist');
          openQuickActionModal(action, '');
        });
      });

      const ipManageButtons = app.querySelectorAll('[data-manage-ip]');
      ipManageButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          const ip = String(btn.getAttribute('data-manage-ip') || '');
          openQuickActionModal('blacklist', ip);
        });
      });

      const policyToggles = app.querySelectorAll('.policy-toggle');
      policyToggles.forEach(function (toggle) {
        toggle.addEventListener('change', async function () {
          const key = String(toggle.getAttribute('data-key') || '');
          const checked = !!toggle.checked;
          try {
            const result = await api('/__shield/admin/protection', {
              method: 'POST',
              body: JSON.stringify({ updates: { [key]: checked } }),
            });
            runtimePolicy = result.policy || runtimePolicy;
            showToast('Policy updated: ' + key, 'ok');
          } catch (err) {
            toggle.checked = !checked;
            showToast(err && err.message ? err.message : 'Policy update failed', 'error');
          }
        });
      });

      const addSiteBtn = document.getElementById('addSiteBtn');
      if (addSiteBtn) {
        addSiteBtn.onclick = function () {
          openAddSiteModal();
        };
      }

      const siteToggles = app.querySelectorAll('[data-site-toggle]');
      siteToggles.forEach(function (btn) {
        btn.addEventListener('click', async function () {
          const domain = String(btn.getAttribute('data-site-toggle') || '');
          const active = String(btn.getAttribute('data-site-active') || '') === '1';
          btn.disabled = true;
          try {
            await api('/__shield/admin/sites/toggle', {
              method: 'POST',
              body: JSON.stringify({ domain: domain, active: !active }),
            });
            sitesCache = null;
            showToast(domain + (active ? ' disabled' : ' enabled'), 'ok');
            await renderDashboard();
          } catch (err) {
            showToast(err && err.message ? err.message : 'Toggle failed', 'error');
          } finally {
            btn.disabled = false;
          }
        });
      });

      const siteRemovals = app.querySelectorAll('[data-site-remove]');
      siteRemovals.forEach(function (btn) {
        btn.addEventListener('click', function () {
          openRemoveSiteModal(String(btn.getAttribute('data-site-remove') || ''));
        });
      });
    }

    async function renderDashboard(seedStats) {
      if (!app || rendering) return;
      rendering = true;

      try {
        let stats = seedStats || null;
        if (!stats) {
          try {
            stats = await api('/__shield/admin/dashboard');
          } catch (err) {
            if (err && err.status === 401) {
              clearToken();
              renderLogin('Session expired. Login again.');
              return;
            }
            renderLogin(err && err.message ? err.message : 'Failed to load dashboard');
            return;
          }
        }

        await loadPolicyIfNeeded();
        await loadSitesIfNeeded();

        app.innerHTML = '<div class="shell">'
          + sidebar()
          + '<section class="workspace">'
          + toolbar(stats)
          + '<main class="content">' + renderTab(stats) + '</main>'
          + '</section>'
          + '</div>';

        bindEvents(stats);
        drawTrafficChart(stats);
      } finally {
        rendering = false;
      }
    }

    function startPolling() {
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = setInterval(function () {
        if (document.visibilityState === 'hidden') return;
        if (document.getElementById('loginForm')) return;
        renderDashboard();
      }, 7000);
    }

    async function bootstrap() {
      try {
        if (INITIAL_STATS) {
          await renderDashboard(INITIAL_STATS);
        } else {
          await renderDashboard();
        }
      } catch (err) {
        renderLogin(err && err.message ? err.message : 'Dashboard initialization failed');
      }
      startPolling();
    }

    window.addEventListener('error', function (ev) {
      const msg = ev && ev.message ? ev.message : 'Unknown runtime error';
      renderLogin('Client error: ' + msg);
    });

    bootstrap();
  })();
  </script>
</body>
</html>`;
}
