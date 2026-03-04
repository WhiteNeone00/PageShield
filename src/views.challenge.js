/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — HTML Templates
   Challenge page, block pages, error pages
   ═══════════════════════════════════════════════════════════════════ */

import { clip, severityLabel } from './core.utils.js';

// ─── Shared Block Page Base ──────────────────────────────────────
function blockPageBase(opts) {
  const {
    host = '', rayId = '', title = 'Access Denied', subtitle = '',
    reason = '', icon = '\uD83D\uDEE1\uFE0F', accentColor = '#e74c3c',
    secondaryColor = '#ff6b6b', statusText = 'Blocked', extraInfo = '',
    showContact = true, retryAfter = 0,
    announcementText = '', richParticles = false,
  } = opts;
  const particlesHtml = richParticles
    ? `
    <div class="particle" style="left:8%;--dur:7s;--delay:0s"></div>
    <div class="particle" style="left:18%;--dur:9s;--delay:1.2s"></div>
    <div class="particle" style="left:28%;--dur:6s;--delay:2.4s"></div>
    <div class="particle" style="left:42%;--dur:10s;--delay:.5s"></div>
    <div class="particle" style="left:55%;--dur:7.5s;--delay:1.8s"></div>
    <div class="particle" style="left:68%;--dur:8.5s;--delay:.8s"></div>
    <div class="particle" style="left:78%;--dur:6.5s;--delay:3s"></div>
    <div class="particle" style="left:88%;--dur:9.5s;--delay:2s"></div>
    <div class="particle" style="left:95%;--dur:7s;--delay:1s"></div>
    <div class="particle" style="left:35%;--dur:11s;--delay:3.5s"></div>`
    : `
    <div class="particle" style="left:12%;--dur:7s;--delay:0s"></div>
    <div class="particle" style="left:28%;--dur:9s;--delay:1.2s"></div>
    <div class="particle" style="left:45%;--dur:6s;--delay:2.4s"></div>
    <div class="particle" style="left:62%;--dur:10s;--delay:.5s"></div>
    <div class="particle" style="left:78%;--dur:8.5s;--delay:.8s"></div>
    <div class="particle" style="left:92%;--dur:7s;--delay:1s"></div>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title} — Ryzeon Shield</title>
<style>
  :root{--bg:#060d1a;--bg-2:#0d1830;--card:rgba(14,24,44,.92);--text:#e8eefc;--muted:#a7b4d3;--accent:${accentColor};--accent-2:${secondaryColor}}
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 10% 12%,color-mix(in srgb,var(--accent) 18%,transparent) 0,transparent 34%),radial-gradient(circle at 92% 88%,color-mix(in srgb,var(--accent-2) 14%,transparent) 0,transparent 34%),linear-gradient(160deg,var(--bg),var(--bg-2));color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;overflow:hidden}
  .particles{position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:0}
  .particle{position:absolute;width:4px;height:4px;border-radius:50%;background:var(--accent);opacity:0;animation:floatUp var(--dur,8s) var(--delay,0s) infinite ease-in}
  .particle:nth-child(even){background:var(--accent-2)}
  @keyframes floatUp{0%{opacity:0;transform:translateY(100vh) scale(.5)}10%{opacity:.5}90%{opacity:.3}100%{opacity:0;transform:translateY(-10vh) scale(1.2)}}
  .announce{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:3;display:flex;align-items:center;gap:12px;max-width:min(94vw,920px);padding:14px 22px;border-radius:24px;border:1px solid color-mix(in srgb,var(--accent) 48%,#dff3ff 18%);background:linear-gradient(130deg,color-mix(in srgb,var(--accent) 26%,transparent),color-mix(in srgb,var(--accent-2) 22%,transparent) 38%,rgba(14,24,44,.84) 100%);backdrop-filter:blur(14px) saturate(135%);box-shadow:0 20px 44px rgba(0,0,0,.38),0 0 0 1px color-mix(in srgb,var(--accent) 34%,transparent) inset,0 0 28px color-mix(in srgb,var(--accent-2) 25%,transparent);animation:announcePop .7s cubic-bezier(.2,1.35,.5,1) .15s both}
  @keyframes announcePop{0%{opacity:0;transform:translateX(-50%) translateY(-28px) scale(.92)}70%{opacity:1;transform:translateX(-50%) translateY(3px) scale(1.02)}100%{opacity:1;transform:translateX(-50%) translateY(0) scale(1)}}
  .announce-dot{width:12px;height:12px;border-radius:50%;background:var(--accent-2);box-shadow:0 0 0 0 color-mix(in srgb,var(--accent-2) 55%,transparent),0 0 14px color-mix(in srgb,var(--accent-2) 50%,transparent);animation:announcePulse 1.7s infinite}
  @keyframes announcePulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--accent-2) 55%,transparent),0 0 14px color-mix(in srgb,var(--accent-2) 50%,transparent)}70%{box-shadow:0 0 0 10px rgba(0,0,0,0),0 0 16px color-mix(in srgb,var(--accent-2) 26%,transparent)}100%{box-shadow:0 0 0 0 rgba(0,0,0,0),0 0 14px color-mix(in srgb,var(--accent-2) 38%,transparent)}}
  .announce-text{font-size:.95rem;line-height:1.38;color:#ecf8ff;letter-spacing:.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .announce-text strong{color:var(--accent-2);font-weight:700}
  .bg-glow{position:fixed;width:28rem;height:28rem;border-radius:50%;filter:blur(90px);opacity:.15;pointer-events:none;z-index:0}
  .bg-glow.one{background:var(--accent);top:-8rem;left:-8rem;animation:glowPulse 6s ease-in-out infinite alternate}
  .bg-glow.two{background:var(--accent-2);right:-8rem;bottom:-10rem;animation:glowPulse 6s ease-in-out 3s infinite alternate}
  @keyframes glowPulse{0%{opacity:.12;transform:scale(1)}100%{opacity:.22;transform:scale(1.15)}}
  .card{position:relative;z-index:1;width:min(560px,92vw);padding:36px;border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);border-radius:24px;background:var(--card);backdrop-filter:blur(14px);box-shadow:0 28px 70px rgba(0,0,0,.55),0 0 0 1px color-mix(in srgb,var(--accent) 8%,transparent) inset;text-align:center;animation:dropIn .85s cubic-bezier(.34,1.56,.64,1) both;transform-style:preserve-3d;transition:transform .15s ease-out}
  @keyframes dropIn{0%{opacity:0;transform:translateY(-120px) scale(.92)}60%{opacity:1;transform:translateY(12px) scale(1.015)}80%{transform:translateY(-4px) scale(1)}100%{opacity:1;transform:translateY(0) scale(1)}}
  .icon-wrap{font-size:3.2rem;margin-bottom:8px;animation:iconPulse 2.5s ease-in-out infinite}
  @keyframes iconPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.06)}}
  h1{font-size:1.55rem;margin-bottom:10px;color:var(--accent);letter-spacing:.3px;animation:fadeIn .6s .3s both}
  .subtitle{color:var(--muted);line-height:1.6;font-size:.94rem;margin-bottom:6px;animation:fadeIn .6s .4s both}
  .reason-box{margin:16px 0;padding:12px 18px;border-radius:14px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 18%,transparent);font-size:.9rem;animation:fadeIn .5s .5s both}
  .reason-box strong{color:var(--accent)}
  .status-badge{display:inline-flex;align-items:center;gap:6px;margin-top:14px;padding:6px 14px;border-radius:20px;font-size:.82rem;font-weight:600;background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent) 25%,transparent);animation:fadeIn .5s .6s both}
  .status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);animation:dotPulse 1.5s infinite}
  @keyframes dotPulse{0%,100%{opacity:1}50%{opacity:.4}}
  @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
  .contact{margin-top:16px;font-size:.86rem;color:#667a9e;animation:fadeIn .5s .7s both}
  .extra{margin-top:14px;font-size:.82rem;color:var(--muted);border-left:3px solid var(--accent-2);padding:8px 12px;text-align:left;border-radius:0 8px 8px 0;background:color-mix(in srgb,var(--accent-2) 6%,transparent);animation:fadeIn .5s .8s both}
  .meta{margin-top:18px;color:#9fb0d0;font-size:.78rem;border-top:1px solid rgba(255,255,255,.08);padding-top:14px;display:flex;flex-wrap:wrap;gap:10px 18px;justify-content:center;animation:fadeIn .5s .9s both}
  .meta strong{color:#d7e3fb;font-weight:600}
  .powered{text-align:center;margin-top:14px;font-size:.72rem;color:rgba(167,180,211,.45);letter-spacing:.05em;animation:fadeIn .5s 1s both}
  @media (max-width:640px){.announce{top:10px;padding:11px 14px;gap:9px;border-radius:18px}.announce-text{font-size:.85rem}}
  ${retryAfter > 0 ? `.retry-timer{margin-top:12px;font-size:.88rem;color:var(--accent-2);font-weight:600;animation:fadeIn .5s .65s both}` : ''}
</style>
</head>
<body>
  ${announcementText ? `<div class="announce" role="status" aria-live="polite"><span class="announce-dot"></span><span class="announce-text"><strong>Ryzeon Notice:</strong> ${clip(announcementText, 120)}</span></div>` : ''}
  <div class="particles">
    ${particlesHtml}
  </div>
  <div class="bg-glow one"></div>
  <div class="bg-glow two"></div>
  <main class="card" id="card">
    <div class="icon-wrap">${icon}</div>
    <h1>${title}</h1>
    <p class="subtitle">${subtitle}</p>
    ${reason ? `<div class="reason-box"><strong>Reason:</strong> ${clip(reason, 120)}</div>` : ''}
    <div class="status-badge"><span class="status-dot"></span>${statusText}</div>
    ${retryAfter > 0 ? `<div class="retry-timer">Retry in <span id="retry-sec">${retryAfter}</span>s</div>` : ''}
    ${extraInfo ? `<div class="extra">${extraInfo}</div>` : ''}
    ${showContact ? '<p class="contact">If you believe this is an error, please contact the site administrator.</p>' : ''}
    <div class="meta">
      <span><strong>Ray ID:</strong> ${rayId}</span>
      <span><strong>Host:</strong> ${host}</span>
    </div>
    <div class="powered">Powered by Ryzeon Shield v3</div>
  </main>
<script>
(()=>{
  var c=document.getElementById('card');
  if(c){c.addEventListener('animationend',function(){c.style.animation='none';});
  var M=8;c.addEventListener('mousemove',function(e){var r=c.getBoundingClientRect();var px=(e.clientX-r.left)/r.width;var py=(e.clientY-r.top)/r.height;c.style.transform='perspective(1000px) rotateX('+((0.5-py)*M*2)+'deg) rotateY('+((px-0.5)*M*2)+'deg) scale3d(1.01,1.01,1.01)';});
  c.addEventListener('mouseleave',function(){c.style.transform='perspective(1000px) rotateX(0) rotateY(0) scale3d(1,1,1)';});}
  ${retryAfter > 0 ? `var s=${retryAfter};var el=document.getElementById('retry-sec');if(el){var t=setInterval(function(){s--;if(s<=0){clearInterval(t);location.reload();}el.textContent=s;},1000);}` : ''}
})();
</script>
</body>
</html>`;
}

// ─── Rate Limited Page ───────────────────────────────────────────
export function htmlRateLimited(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'Rate Limited',
    subtitle: 'You are sending too many requests. Please slow down and try again shortly.',
    reason: 'Too many requests from your IP address',
    icon: '\u26A1', accentColor: '#e67e22', secondaryColor: '#f39c12',
    statusText: 'Rate Limited', retryAfter: 60,
    extraInfo: 'Your request rate has exceeded the allowed limit. This restriction is temporary and will be lifted automatically.',
    announcementText: 'Traffic shaping is active — excessive request bursts are temporarily delayed to protect service stability.',
  });
}

// ─── VPN/Proxy Detected Page ─────────────────────────────────────
export function htmlVpnBlocked(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'VPN / Proxy Detected',
    subtitle: 'Your connection appears to be routed through a VPN, proxy, or data center network.',
    reason: 'VPN or proxy network detected',
    icon: '\uD83D\uDD12', accentColor: '#9b59b6', secondaryColor: '#8e44ad',
    statusText: 'Proxy Detected',
    extraInfo: 'For security reasons, connections from known VPN and proxy services are restricted. Please disconnect your VPN and try again.',
  });
}

// ─── Suspended / Penalized Page ──────────────────────────────────
export function htmlSuspended(host, rayId, reason) {
  return blockPageBase({
    host, rayId,
    title: 'Access Suspended',
    subtitle: 'Your access has been temporarily or permanently suspended due to repeated violations.',
    reason: reason || 'Multiple security violations detected',
    icon: '\uD83D\uDEAB', accentColor: '#992d22', secondaryColor: '#c0392b',
    statusText: 'Suspended',
    extraInfo: 'Your IP address has been penalized due to repeated malicious activity. If this suspension is permanent, contact the site administrator.',
    announcementText: 'Security enforcement is active — this access path is currently restricted due to policy violations.',
  });
}

// ─── Country Blocked Page ────────────────────────────────────────
export function htmlCountryBlocked(host, rayId, country) {
  return blockPageBase({
    host, rayId,
    title: 'Region Restricted',
    subtitle: 'Access from your geographic region is not permitted on this service.',
    reason: 'Country blocked: ' + (country || 'Unknown'),
    icon: '\uD83C\uDF10', accentColor: '#546e7a', secondaryColor: '#78909c',
    statusText: 'Geo-Restricted',
    extraInfo: 'This website restricts access from certain countries or regions. This policy is set by the site administrator.',
  });
}

// ─── DDoS Detected Page ─────────────────────────────────────────
export function htmlDdosBlocked(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'DDoS Attack Detected',
    subtitle: 'Abnormal traffic patterns consistent with a distributed denial-of-service attack have been detected from your connection.',
    reason: 'Distributed denial-of-service anomaly',
    icon: '\uD83C\uDF0A', accentColor: '#e74c3c', secondaryColor: '#ff4757',
    statusText: 'DDoS Mitigated', retryAfter: 120,
    extraInfo: 'If you are a legitimate visitor, this may have been triggered by unusual network activity. Please wait and try again.',
  });
}

// ─── AI Crawler Blocked Page ─────────────────────────────────────
export function htmlAiCrawlerBlocked(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'AI Crawler Blocked',
    subtitle: 'Automated AI data collection bots are not permitted to access this website.',
    reason: 'AI crawler / scraper detected',
    icon: '\uD83E\uDD16', accentColor: '#00b4d8', secondaryColor: '#0096c7',
    statusText: 'AI Bot Blocked',
    extraInfo: 'This site does not allow AI training bots, scrapers, or automated data collection tools. If you are a legitimate user, please use a standard browser.',
  });
}

// ─── Bot / Headless Detected Page ────────────────────────────────
export function htmlBotDetected(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'Bot Detected',
    subtitle: 'Your request appears to originate from an automated tool, headless browser, or bot.',
    reason: 'Automated / headless browser detected',
    icon: '\uD83D\uDEA8', accentColor: '#f39c12', secondaryColor: '#e67e22',
    statusText: 'Bot Detected',
    extraInfo: 'Headless browsers, scraping tools, and automated bots are blocked. Use a standard browser with JavaScript enabled.',
  });
}

// ─── Attack Detected Page ────────────────────────────────────────
export function htmlAttackBlocked(host, rayId, attackTypes) {
  return blockPageBase({
    host, rayId,
    title: 'Malicious Request Blocked',
    subtitle: 'Your request contained patterns associated with a known attack vector.',
    reason: 'Attack signature: ' + (attackTypes || 'Unknown'),
    icon: '\u2620\uFE0F', accentColor: '#ff0000', secondaryColor: '#cc0000',
    statusText: 'Attack Blocked',
    showContact: true,
    extraInfo: 'The request was identified as potentially malicious and has been permanently blocked. Repeated attacks will result in extended bans.',
  });
}

// ─── Honeypot Triggered Page ─────────────────────────────────────
export function htmlHoneypotTriggered(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'Permanently Banned',
    subtitle: 'Your IP address has been permanently banned for accessing restricted trap endpoints.',
    reason: 'Honeypot trap triggered — permanent ban applied',
    icon: '\uD83C\uDF6F', accentColor: '#eb459e', secondaryColor: '#fe73b1',
    statusText: 'Permanent Ban', showContact: false,
    extraInfo: 'You attempted to access a restricted endpoint designed to detect malicious scanners. This ban is permanent and cannot be appealed.',
  });
}

// ─── Service Unavailable Page ────────────────────────────────────
export function htmlServiceDown(host, rayId) {
  return blockPageBase({
    host, rayId,
    title: 'Service Unavailable',
    subtitle: 'The origin server is currently unavailable. Please try again later.',
    reason: 'Origin server unreachable',
    icon: '\uD83D\uDEE0\uFE0F', accentColor: '#636e72', secondaryColor: '#b2bec3',
    statusText: 'Service Down', retryAfter: 30,
    showContact: true,
    extraInfo: 'The server may be undergoing maintenance or experiencing temporary issues. Your request will be served once the service recovers.',
    announcementText: 'Service health monitoring is active — origin is currently unavailable and traffic is safely queued behind edge protection.',
    richParticles: true,
  });
}

// ─── Visual Challenge HTML (with behavioral analysis + enhanced fingerprinting) ─
export function htmlChallenge(host, rayId, colo, utcTime, threatScore) {
  const severity = severityLabel(threatScore);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Ryzeon Shield</title>
<style>
  :root{--bg:#060d1a;--bg-2:#0d1830;--card:rgba(14,24,44,.85);--text:#e8eefc;--muted:#a7b4d3;--accent:#56a0ff;--accent-2:#00bcbc;--danger:#e74c3c}
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 10% 12%,rgba(86,160,255,.22) 0,transparent 34%),radial-gradient(circle at 92% 88%,rgba(0,188,188,.18) 0,transparent 34%),linear-gradient(160deg,var(--bg),var(--bg-2));color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;overflow:hidden;perspective:1000px}
  .particles{position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:0}
  .particle{position:absolute;width:4px;height:4px;border-radius:50%;background:var(--accent);opacity:0;animation:floatUp var(--dur,8s) var(--delay,0s) infinite ease-in}
  .particle:nth-child(even){background:var(--accent-2)}
  @keyframes floatUp{0%{opacity:0;transform:translateY(100vh) scale(.5)}10%{opacity:.6}90%{opacity:.4}100%{opacity:0;transform:translateY(-10vh) scale(1.2)}}
  .bg-glow{position:fixed;width:28rem;height:28rem;border-radius:50%;filter:blur(90px);opacity:.18;pointer-events:none;z-index:0}
  .bg-glow.one{background:var(--accent);top:-8rem;left:-8rem;animation:glowPulse 6s ease-in-out infinite alternate}
  .bg-glow.two{background:var(--accent-2);right:-8rem;bottom:-10rem;animation:glowPulse 6s ease-in-out 3s infinite alternate}
  @keyframes glowPulse{0%{opacity:.14;transform:scale(1)}100%{opacity:.24;transform:scale(1.15)}}
  .announce{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:3;display:flex;align-items:center;gap:12px;max-width:min(94vw,920px);padding:14px 22px;border-radius:24px;border:1px solid rgba(156,225,255,.45);background:linear-gradient(130deg,rgba(80,170,255,.22),rgba(0,188,188,.2) 38%,rgba(14,24,44,.84) 100%);backdrop-filter:blur(14px) saturate(135%);box-shadow:0 20px 44px rgba(0,0,0,.38),0 0 0 1px rgba(140,215,255,.2) inset,0 0 28px rgba(0,188,188,.16);animation:announcePop .7s cubic-bezier(.2,1.35,.5,1) .15s both}
  @keyframes announcePop{0%{opacity:0;transform:translateX(-50%) translateY(-28px) scale(.92)}70%{opacity:1;transform:translateX(-50%) translateY(3px) scale(1.02)}100%{opacity:1;transform:translateX(-50%) translateY(0) scale(1)}}
  .announce-dot{width:12px;height:12px;border-radius:50%;background:#9ff4ff;box-shadow:0 0 0 0 rgba(159,244,255,.6),0 0 14px rgba(159,244,255,.5);animation:announcePulse 1.7s infinite}
  @keyframes announcePulse{0%{box-shadow:0 0 0 0 rgba(0,188,188,.55)}70%{box-shadow:0 0 0 10px rgba(0,188,188,0)}100%{box-shadow:0 0 0 0 rgba(0,188,188,0)}}
  .announce-text{font-size:.95rem;line-height:1.38;color:#ecf8ff;letter-spacing:.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .announce-text strong{color:var(--accent-2);font-weight:700}
  @media (max-width:640px){.announce{top:10px;padding:11px 14px;gap:9px;border-radius:18px}.announce-text{font-size:.85rem}}
  .card{position:relative;z-index:1;width:min(640px,92vw);padding:34px 36px;border:1px solid rgba(120,140,180,.22);border-radius:24px;background:var(--card);backdrop-filter:blur(14px);box-shadow:0 28px 70px rgba(0,0,0,.5),0 0 0 1px rgba(86,160,255,.06) inset;animation:dropIn .85s cubic-bezier(.34,1.56,.64,1) both;transition:transform .15s ease-out;transform-style:preserve-3d}
  @keyframes dropIn{0%{opacity:0;transform:translateY(-120px) scale(.92)}60%{opacity:1;transform:translateY(12px) scale(1.015)}80%{transform:translateY(-4px) scale(1)}100%{opacity:1;transform:translateY(0) scale(1)}}
  .head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:6px}
  .brand{display:flex;flex-direction:column;gap:2px}
  .brand-kicker{font-size:.76rem;letter-spacing:.12em;text-transform:uppercase;color:var(--accent-2);font-weight:700;animation:fadeIn .6s .3s both}
  .brand-title{font-size:1.18rem;font-weight:700;color:#eaf1ff;letter-spacing:.3px;animation:fadeIn .6s .4s both}
  @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
  .logo{width:56px;height:56px;border-radius:14px;display:block;border:1px solid rgba(232,238,252,.18);animation:logoFloat 4s ease-in-out infinite}
  @keyframes logoFloat{0%,100%{transform:translateY(0) rotate(0deg)}50%{transform:translateY(-6px) rotate(2deg)}}
  .shield-icon{display:flex;align-items:center;justify-content:center;margin:12px auto 8px;width:64px;height:64px;animation:shieldPulse 2.5s ease-in-out infinite}
  .shield-icon svg{width:48px;height:48px;fill:var(--accent);filter:drop-shadow(0 0 12px rgba(86,160,255,.4))}
  @keyframes shieldPulse{0%,100%{transform:scale(1);filter:drop-shadow(0 0 8px rgba(86,160,255,.3))}50%{transform:scale(1.08);filter:drop-shadow(0 0 18px rgba(86,160,255,.6))}}
  h1{margin:6px 0 8px;font-size:1.6rem;letter-spacing:.2px;text-align:center;animation:fadeIn .6s .5s both}
  .subtitle{text-align:center;color:var(--muted);line-height:1.55;font-size:.95rem;animation:fadeIn .6s .6s both}
  .loading-wrap{margin:20px 0 0;display:flex;align-items:center;gap:14px;animation:fadeIn .5s .7s both}
  .loader-ring{width:38px;height:38px;border-radius:50%;flex-shrink:0;border:3px solid rgba(255,255,255,.1);border-top-color:var(--accent);border-right-color:var(--accent-2);animation:spin .85s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .timer{font-weight:700;color:var(--accent);font-size:1.05rem}
  .dots{display:inline-flex;gap:5px;margin-left:4px;vertical-align:middle}
  .dots span{width:6px;height:6px;border-radius:50%;background:var(--accent-2);opacity:.3;animation:blink 1.2s infinite}
  .dots span:nth-child(2){animation-delay:.2s}
  .dots span:nth-child(3){animation-delay:.4s}
  @keyframes blink{0%,80%,100%{opacity:.2;transform:translateY(0)}40%{opacity:1;transform:translateY(-2px)}}
  .bar{margin-top:14px;height:6px;border-radius:999px;background:rgba(255,255,255,.1);overflow:hidden}
  .bar>span{display:block;height:100%;width:100%;background:linear-gradient(90deg,var(--accent),var(--accent-2));transform-origin:left;animation:countdown 10s linear forwards}
  @keyframes countdown{from{transform:scaleX(1)}to{transform:scaleX(0)}}
  .status-badge{display:inline-flex;align-items:center;gap:6px;margin-top:14px;padding:6px 14px;border-radius:20px;font-size:.82rem;font-weight:600;background:rgba(86,160,255,.12);border:1px solid rgba(86,160,255,.25);animation:fadeIn .5s .8s both}
  .status-dot{width:8px;height:8px;border-radius:50%;background:var(--accent-2);animation:dotPulse 1.5s infinite}
  @keyframes dotPulse{0%,100%{opacity:1}50%{opacity:.4}}
  .warn{margin-top:14px;color:#e8eefc;font-size:.92rem;border-left:3px solid var(--accent-2);padding:8px 12px;border-radius:0 8px 8px 0;background:rgba(0,188,188,.06);animation:slideRight .5s ease .9s both}
  @keyframes slideRight{from{opacity:0;transform:translateX(-12px)}to{opacity:1;transform:translateX(0)}}
  .meta{margin-top:18px;color:#9fb0d0;font-size:.8rem;border-top:1px solid rgba(255,255,255,.1);padding-top:14px;line-height:1.6;display:flex;flex-wrap:wrap;gap:12px 20px;justify-content:center;text-align:center;animation:fadeIn .5s 1s both}
  .meta-item{white-space:nowrap}
  .meta strong{color:#d7e3fb;font-weight:600}
  .powered{text-align:center;margin-top:16px;font-size:.72rem;color:rgba(167,180,211,.5);letter-spacing:.05em;animation:fadeIn .5s 1.1s both}
  .hp-field{position:absolute;left:-9999px;opacity:0;height:0;width:0;overflow:hidden;pointer-events:none;tab-index:-1}
</style>
</head>
<body>
  <div class="announce" role="status" aria-live="polite">
    <span class="announce-dot"></span>
    <span class="announce-text"><strong>Ryzeon Notice:</strong> Enhanced verification is live — fast, secure, and actively filtering abusive traffic.</span>
  </div>
  <div class="particles">
    <div class="particle" style="left:8%;--dur:7s;--delay:0s"></div>
    <div class="particle" style="left:18%;--dur:9s;--delay:1.2s"></div>
    <div class="particle" style="left:28%;--dur:6s;--delay:2.4s"></div>
    <div class="particle" style="left:42%;--dur:10s;--delay:.5s"></div>
    <div class="particle" style="left:55%;--dur:7.5s;--delay:1.8s"></div>
    <div class="particle" style="left:68%;--dur:8.5s;--delay:.8s"></div>
    <div class="particle" style="left:78%;--dur:6.5s;--delay:3s"></div>
    <div class="particle" style="left:88%;--dur:9.5s;--delay:2s"></div>
    <div class="particle" style="left:95%;--dur:7s;--delay:1s"></div>
    <div class="particle" style="left:35%;--dur:11s;--delay:3.5s"></div>
  </div>
  <div class="bg-glow one"></div>
  <div class="bg-glow two"></div>
  <main class="card" id="card">
    <div class="head">
      <div class="brand">
        <span class="brand-kicker">Protection Active</span>
        <span class="brand-title">Ryzeon Shield</span>
      </div>
      <img class="logo" src="https://${host}/image.png" onerror="this.style.display='none'" alt="logo"/>
    </div>
    <div class="shield-icon">
      <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
      </svg>
    </div>
    <h1>Verifying your connection</h1>
    <p class="subtitle">Ryzeon Shield is checking your browser. This automatic security process will complete shortly.</p>
    <!-- Hidden honeypot fields -->
    <input class="hp-field" type="text" name="website" id="hp-website" autocomplete="off" tabindex="-1"/>
    <input class="hp-field" type="email" name="email_confirm" id="hp-email" autocomplete="off" tabindex="-1"/>
    <div class="loading-wrap">
      <div class="loader-ring"></div>
      <div class="timer"><span id="status-text">Verifying your browser</span> <span id="sec"></span><span class="dots"><span></span><span></span><span></span></span></div>
    </div>
    <div class="bar"><span></span></div>
    <div class="status-badge"><span class="status-dot"></span>Security check in progress</div>
    <div class="warn">This site is protected by <strong>Ryzeon Shield</strong>. Automated or unauthorized access is strictly prohibited.</div>
    <div class="meta">
      <div class="meta-item"><strong>Ray ID:</strong> ${rayId}</div>
      <div class="meta-item"><strong>Datacenter:</strong> ${colo}</div>
      <div class="meta-item"><strong>UTC:</strong> ${utcTime}</div>
      <div class="meta-item"><strong>Threat Level:</strong> ${severity}</div>
    </div>
    <div class="powered">Powered by Ryzeon Shield v3</div>
  </main>
<script>
(function(){
  /* ── Behavioral Analysis Tracker ── */
  var beh={mouseCount:0,mouseDistance:0,lastMX:0,lastMY:0,clicks:[],scrollEvents:0,scrollTotal:0,keyPresses:0,keyIntervals:[],lastKeyTime:0,touchCount:0,startTime:Date.now(),focusChanges:0,pasteCount:0};
  document.addEventListener('mousemove',function(e){
    beh.mouseCount++;
    if(beh.lastMX||beh.lastMY){beh.mouseDistance+=Math.sqrt(Math.pow(e.clientX-beh.lastMX,2)+Math.pow(e.clientY-beh.lastMY,2));}
    beh.lastMX=e.clientX;beh.lastMY=e.clientY;
  });
  document.addEventListener('click',function(){beh.clicks.push(Date.now()-beh.startTime);});
  document.addEventListener('scroll',function(){beh.scrollEvents++;beh.scrollTotal+=Math.abs(window.scrollY);});
  document.addEventListener('keydown',function(){
    var now=Date.now();beh.keyPresses++;
    if(beh.lastKeyTime>0)beh.keyIntervals.push(now-beh.lastKeyTime);
    beh.lastKeyTime=now;
  });
  document.addEventListener('touchstart',function(){beh.touchCount++;});
  window.addEventListener('blur',function(){beh.focusChanges++;});
  window.addEventListener('focus',function(){beh.focusChanges++;});
  document.addEventListener('paste',function(){beh.pasteCount++;});

  function getBehaviorSignals(){
    var duration=(Date.now()-beh.startTime)/1000;
    var avgKeyInterval=beh.keyIntervals.length>0?beh.keyIntervals.reduce(function(a,b){return a+b},0)/beh.keyIntervals.length:0;
    var clickTimings=[];
    for(var i=1;i<beh.clicks.length;i++)clickTimings.push(beh.clicks[i]-beh.clicks[i-1]);
    var avgClickInterval=clickTimings.length>0?clickTimings.reduce(function(a,b){return a+b},0)/clickTimings.length:0;
    return{
      mouseCount:beh.mouseCount,
      mouseDistance:Math.round(beh.mouseDistance),
      mouseDensity:duration>0?Math.round(beh.mouseCount/duration):0,
      clicks:beh.clicks.length,
      avgClickInterval:Math.round(avgClickInterval),
      scrollEvents:beh.scrollEvents,
      keyPresses:beh.keyPresses,
      avgKeyInterval:Math.round(avgKeyInterval),
      touchCount:beh.touchCount,
      focusChanges:beh.focusChanges,
      pasteCount:beh.pasteCount,
      duration:Math.round(duration*1000)
    };
  }

  /* ── Honeypot Check ── */
  function checkHoneypots(){
    var hp1=document.getElementById('hp-website');
    var hp2=document.getElementById('hp-email');
    return{website:hp1?hp1.value:'',email:hp2?hp2.value:''};
  }

  /* ── Crypto ── */
  function digest(v){
    return crypto.subtle.digest('SHA-256',new TextEncoder().encode(v)).then(function(b){
      return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,'0')}).join('');
    });
  }

  function solvePoW(prefix,difficulty){
    var target='';for(var i=0;i<difficulty;i++)target+='0';
    return new Promise(function(resolve){
      var nn=0;
      function asyncSolve(){
        var promises=[];
        var batchStart=nn;
        var batchSize=500;
        for(var j=0;j<batchSize;j++){
          promises.push(digest(prefix+':'+(batchStart+j)));
        }
        Promise.all(promises).then(function(results){
          for(var k=0;k<results.length;k++){
            if(results[k].substring(0,difficulty)===target){
              resolve({nonce:batchStart+k,hash:results[k]});
              return;
            }
          }
          nn+=batchSize;
          setTimeout(asyncSolve,0);
        });
      }
      asyncSolve();
    });
  }

  /* ── Enhanced Fingerprint Collection ── */
  function collectFingerprint(){
    try{
      var fontsProbe=['Arial','Verdana','Tahoma','Times New Roman','Courier New','Inter','Georgia','Helvetica'];
      var fontData=fontsProbe.map(function(f){return f+':'+(document.fonts&&document.fonts.check?document.fonts.check('12px '+f):false)}).join('|');

      // Canvas fingerprint
      var canvasFp='na';
      try{var cv=document.createElement('canvas');var cx=cv.getContext('2d');cx.textBaseline='top';cx.font='14px Arial';cx.fillStyle='#f60';cx.fillRect(125,1,62,20);cx.fillStyle='#069';cx.fillText('Ryzeon\\uD83D\\uDEE1',2,15);cx.fillStyle='rgba(102,204,0,.7)';cx.fillText('Shield',4,17);canvasFp=cv.toDataURL().slice(0,200);}catch(e){}

      // WebGL fingerprint
      var webglFp='na';
      try{var gc=document.createElement('canvas');var gl=gc.getContext('webgl')||gc.getContext('experimental-webgl');if(gl){var dbg=gl.getExtension('WEBGL_debug_renderer_info');var ren=dbg?gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL):'na';var ven=dbg?gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL):'na';var maxTex=gl.getParameter(gl.MAX_TEXTURE_SIZE)||0;var maxVert=gl.getParameter(gl.MAX_VERTEX_ATTRIBS)||0;webglFp=ven+'|'+ren+'|'+maxTex+'|'+maxVert;}}catch(e){}

      // AudioContext fingerprint
      var audioFp='na';
      try{var AudioCtx=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(AudioCtx){var actx=new AudioCtx(1,44100,44100);var osc=actx.createOscillator();osc.type='triangle';osc.frequency.setValueAtTime(10000,actx.currentTime);var comp=actx.createDynamicsCompressor();comp.threshold.setValueAtTime(-50,actx.currentTime);comp.knee.setValueAtTime(40,actx.currentTime);comp.ratio.setValueAtTime(12,actx.currentTime);comp.attack.setValueAtTime(0,actx.currentTime);comp.release.setValueAtTime(.25,actx.currentTime);osc.connect(comp);comp.connect(actx.destination);osc.start(0);actx.startRendering();audioFp=AudioCtx.name||'audio-ok';}}catch(e){}

      // Screen & hardware
      var screenFp=(screen.width||0)+'x'+(screen.height||0)+'x'+(screen.colorDepth||0)+'x'+(screen.pixelDepth||0)+'x'+window.devicePixelRatio;
      var tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';
      var hw=(navigator.hardwareConcurrency||0)+':'+(navigator.deviceMemory||0);
      var plugins=navigator.plugins?navigator.plugins.length:0;
      var langs=navigator.languages?navigator.languages.join(','):navigator.language||'';
      var touchPoints=navigator.maxTouchPoints||0;
      var platform=navigator.platform||'';
      var dnt=navigator.doNotTrack||'unset';
      var cookieEnabled=navigator.cookieEnabled?'1':'0';

      var raw=[
        navigator.userAgent||'',platform,langs,screenFp,tz,hw,
        fontData,canvasFp,webglFp,audioFp,
        plugins,touchPoints,dnt,cookieEnabled
      ].join('||');
      return digest(raw);
    }catch(e){return Promise.resolve('');}
  }

  function collectClientSnapshot(){
    var langs=navigator.languages?navigator.languages.join(','):navigator.language||'unknown';
    var tz='unknown';
    try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'unknown';}catch(e){}
    var sw=screen&&screen.width?screen.width:0;
    var sh=screen&&screen.height?screen.height:0;
    var plugins=navigator.plugins?navigator.plugins.length:0;
    var fontFamilies=['Arial','Verdana','Tahoma','Times New Roman','Courier New','Inter','Georgia','Helvetica','Roboto','Segoe UI'];
    var fontsCount=0;
    if(document.fonts&&document.fonts.check){
      for(var i=0;i<fontFamilies.length;i++){
        if(document.fonts.check('12px '+fontFamilies[i])) fontsCount++;
      }
    }
    var entropy=0;
    if(langs&&langs!=='unknown') entropy+=15;
    if(plugins>0) entropy+=15;
    if(fontsCount>=4) entropy+=20;
    if(sw>=1024&&sh>=600) entropy+=15;
    if(navigator.hardwareConcurrency&&navigator.hardwareConcurrency>=2) entropy+=10;
    if(navigator.deviceMemory&&navigator.deviceMemory>=2) entropy+=10;
    if(window.devicePixelRatio&&window.devicePixelRatio!==1) entropy+=5;
    entropy=Math.max(0,Math.min(100,entropy));
    return{
      timezone:tz,
      screen:String(sw)+'x'+String(sh),
      languages:langs,
      pluginsCount:plugins,
      fontsCount:fontsCount,
      entropyScore:entropy,
    };
  }

  var el=document.getElementById('sec');
  var statusEl=document.getElementById('status-text');
  var startTime=Date.now();
  var MIN_DISPLAY_MS=10000;
  var jsExecStart=performance.now();
  var jsDelayMs=0;
  setTimeout(function(){jsDelayMs=Math.round(performance.now()-jsExecStart);},100);

  collectFingerprint().then(function(fpHash){
    if(statusEl) statusEl.textContent='Initializing security check\\u2026';
    return fetch('/__challenge?fp='+encodeURIComponent(fpHash),{
      method:'GET',
      credentials:'include',
      headers:{'x-shield-fp':fpHash}
    }).then(function(r){return r.json()}).then(function(challenge){
      if(statusEl) statusEl.textContent='Solving proof-of-work\\u2026';
      return solvePoW(challenge.prefix,challenge.difficulty).then(function(solution){
        if(statusEl) statusEl.textContent='Analyzing behavior\\u2026';
        var behaviorData=getBehaviorSignals();
        var honeypotData=checkHoneypots();
        var clientSnapshot=collectClientSnapshot();
        clientSnapshot.jsDelayMs=jsDelayMs;
        if(statusEl) statusEl.textContent='Verifying identity\\u2026';
        return fetch('/__verify',{
          method:'POST',
          credentials:'include',
          headers:{'content-type':'application/json'},
          body:JSON.stringify({
            prefix:challenge.prefix,
            nonce:solution.nonce,
            hash:solution.hash,
            fpHash:fpHash,
            challengeId:challenge.challengeId,
            challengeType:challenge.challengeType||'pow',
            challengeDifficulty:challenge.difficulty,
            challengeSig:challenge.challengeSig,
            challengeIssuedAt:challenge.issuedAt,
            challengeExpiresIn:challenge.expiresIn,
            behavior:behaviorData,
            honeypot:honeypotData,
            client:clientSnapshot
          })
        }).then(function(res){return res.json()});
      });
    });
  }).then(function(json){
    var elapsed=Date.now()-startTime;
    var wait=elapsed<MIN_DISPLAY_MS?MIN_DISPLAY_MS-elapsed:0;
    if(wait>0&&statusEl) statusEl.textContent='Finalizing\\u2026';
    setTimeout(function(){
      if(json&&json.ok){
        if(statusEl) statusEl.textContent='Access granted';
        if(el) el.textContent='\\u2714';
        var badge=document.querySelector('.status-badge');
        if(badge){badge.style.borderColor='rgba(87,242,135,.4)';badge.style.color='#57F287';badge.innerHTML='<span class="status-dot" style="background:#57F287"></span>Verified';}
        var bar=document.querySelector('.bar span');
        if(bar){bar.style.width='100%';bar.style.background='linear-gradient(90deg,#57F287,#00bcbc)';bar.style.animation='none';bar.style.transform='scaleX(1)';}
        setTimeout(function(){
          var card=document.querySelector('.card');
          if(card){card.style.transition='opacity .6s ease,transform .6s ease';card.style.opacity='0';card.style.transform='translateY(-50px) scale(.92)';}
          setTimeout(function(){window.location.href=window.location.href;},700);
        },800);
      }else{
        if(statusEl) statusEl.textContent='Verification failed \\u2014 retrying\\u2026';
        setTimeout(function(){window.location.href=window.location.href;},2000);
      }
    },wait);
  })['catch'](function(){
    if(statusEl) statusEl.textContent='Error \\u2014 retrying\\u2026';
    setTimeout(function(){window.location.href=window.location.href;},2000);
  });

  var s=10;
  if(el) el.textContent='';
  var tick=setInterval(function(){s--;if(s<=0)clearInterval(tick);},1000);

  /* ── Tilt Effect ── */
  var tc=document.getElementById('card');
  if(tc){
    tc.addEventListener('animationend',function(){tc.style.animation='none';});
    var MT=10;
    tc.addEventListener('mousemove',function(e){
      var r=tc.getBoundingClientRect();
      var px=(e.clientX-r.left)/r.width;
      var py=(e.clientY-r.top)/r.height;
      var rx=(0.5-py)*MT*2;
      var ry=(px-0.5)*MT*2;
      tc.style.transform='perspective(1000px) rotateX('+rx+'deg) rotateY('+ry+'deg) scale3d(1.02,1.02,1.02)';
    });
    tc.addEventListener('mouseleave',function(){
      tc.style.transform='perspective(1000px) rotateX(0) rotateY(0) scale3d(1,1,1)';
    });
  }

  /* ── Fake JS variables (honeypot traps for bots) ── */
  window.__RYZEON_SECRET='trap';
  window.__admin_token='eyJhbGciOiJIUzI1NiJ9.fake';
  window.__api_key='sk-fake-'+Math.random().toString(36).substring(2);
  window.__debug_mode=false;
  window.__session_bypass='/api/v2/auth/bypass';
})();
</script>
</body>
</html>`;
}

// ─── Legacy Hard Block (kept for backward compatibility) ─────────
export function htmlHardBlock(host, rayId, reason) {
  return blockPageBase({
    host, rayId,
    title: 'Access Denied',
    subtitle: 'Your request has been blocked by Ryzeon Shield.',
    reason, icon: '\uD83D\uDEE1\uFE0F',
    accentColor: '#e74c3c', secondaryColor: '#ff6b6b',
    statusText: 'Blocked',
  });
}


