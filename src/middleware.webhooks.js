/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Webhooks, Logging & Analytics
   Discord embeds, D1 logging, R2 snapshots, KV stats
   ═══════════════════════════════════════════════════════════════════ */

import { WEBHOOK_COLORS, DISCORD_WORTHY, DEFAULT_LOGO_URL } from './core.config.js';
import { clip, severityLabel, threatBar } from './core.utils.js';

// ─── Deployment Event State ──────────────────────────────────────
let deploymentEventSent = false;
let deploymentEventVersion = '';

// ─── In-Memory Cooldown (survives KV write-limit exhaustion) ─────
const memCooldown = new Map();
const MEM_COOLDOWN_MAX = 2000;

function memCooldownCleanup() {
  if (memCooldown.size <= MEM_COOLDOWN_MAX) return;
  const now = Date.now();
  for (const [k, exp] of memCooldown) {
    if (exp <= now) memCooldown.delete(k);
  }
  if (memCooldown.size > MEM_COOLDOWN_MAX) {
    const entries = [...memCooldown.entries()].sort((a, b) => a[1] - b[1]);
    for (let i = 0, n = Math.floor(entries.length / 2); i < n; i++) memCooldown.delete(entries[i][0]);
  }
}

// ─── Trigger Flags ───────────────────────────────────────────────
function triggerFlags(details) {
  const flags = [];
  if (details._suspicious) flags.push('\uD83D\uDEA8 Bot/Suspicious');
  if (details._headless) flags.push('\uD83E\uDD16 Headless Browser');
  if (details._vpn) flags.push('\uD83D\uDD12 VPN/Proxy/DC');
  if (details._aiCrawler) flags.push('\uD83E\uDDE0 AI Crawler');
  if (details._ddosSuspect) flags.push('\uD83C\uDF0A DDoS/Burst Pattern');
  if (details._spam) flags.push('\u26A1 Rate Limited');
  if (details._fpSpam) flags.push('\uD83D\uDC65 FP Rate Limit');
  if (details._isBotFarm) flags.push('\uD83D\uDC1C Bot Farm');
  if (details._countryAnomaly) flags.push('\uD83C\uDF0D Geo Anomaly');
  if (details._fpHardBlocked) flags.push('\u26D4 FP Hard Blocked');
  if (details._commandLineClient) flags.push('\uD83D\uDDA5\uFE0F CLI HTTP Client');
  if (details._dataCrawlerUa) flags.push('\uD83D\uDD77\uFE0F Data Crawler UA');
  if (details._proxyHeaderAnomaly) flags.push('\uD83E\uDDED Proxy Header Anomaly');
  if (details._longUrlSignal) flags.push('\uD83D\uDCCF Long URL Probe');
  if (details._attackFlags?.length) flags.push('\uD83D\uDEE1\uFE0F Attack: ' + details._attackFlags.join(', '));
  if (details._penaltyPermanent) flags.push('\u267B\uFE0F Permanent Ban');
  return flags;
}

function escalationLabel(action) {
  const map = {
    'block': '\u26D4 HARD BLOCK',
    'pow-hard': '\uD83D\uDD12 PoW Hard',
    'pow': '\uD83E\uDDE9 PoW Standard',
    'pow-lite': '\uD83D\uDD35 PoW Lite',
    'allow': '\u2705 Allow',
  };
  return map[action] || action || 'N/A';
}

function eventMeta(eventType) {
  const map = {
    PASSED: { icon: '✅', banner: 'Request Passed', status: 'Allowed' },
    CHALLENGED: { icon: '🧩', banner: 'Challenge Required', status: 'Challenged' },
    FAILED: { icon: '❌', banner: 'Challenge Failed', status: 'Blocked' },
    BLOCKED: { icon: '🛑', banner: 'Request Blocked', status: 'Blocked' },
    HARD_BLOCKED: { icon: '⛔', banner: 'Hard Block Applied', status: 'Blocked' },
    RATE_LIMITED: { icon: '🚦', banner: 'Rate Limit Triggered', status: 'Throttled' },
    HONEYPOT: { icon: '🍯', banner: 'Honeypot Triggered', status: 'Blocked' },
    HONEYPOT_FORM: { icon: '🕸️', banner: 'Form Trap Triggered', status: 'Blocked' },
    ATTACK: { icon: '🧨', banner: 'Attack Signature Matched', status: 'Blocked' },
    BOT_DETECTED: { icon: '🤖', banner: 'Bot Detected', status: 'Blocked' },
    BOT_FARM: { icon: '🐜', banner: 'Bot Farm Detected', status: 'Blocked' },
    COUNTRY_BLOCKED: { icon: '🌍', banner: 'Country Policy Block', status: 'Blocked' },
    VPN_BLOCKED: { icon: '🕶️', banner: 'VPN / Proxy Block', status: 'Blocked' },
    DEPLOYED: { icon: '🚀', banner: 'System Upgrade Completed', status: 'Live' },
    SYSTEM_UPDATE: { icon: '🆙', banner: 'System Upgrade Completed', status: 'Live' },
    ERROR: { icon: '⚠️', banner: 'System Error', status: 'Attention' },
  };
  return map[eventType] || { icon: '📌', banner: 'Security Event', status: 'Active' };
}

function parseRelease(version) {
  const m = String(version || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)$/i);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
  };
}

function formatRelease(parts) {
  return `v${parts.major}.${parts.minor}.${parts.patch}`;
}

function bumpRelease(current, bumpType) {
  const parsed = parseRelease(current) || { major: 4, minor: 0, patch: 0 };
  if (bumpType === 'major') {
    return formatRelease({ major: parsed.major + 1, minor: 0, patch: 0 });
  }
  if (bumpType === 'minor') {
    return formatRelease({ major: parsed.major, minor: parsed.minor + 1, patch: 0 });
  }
  return formatRelease({ major: parsed.major, minor: parsed.minor, patch: parsed.patch + 1 });
}

function shortVersionId(id) {
  const s = String(id || '').trim();
  return s.length > 12 ? s.slice(0, 8) : s;
}

function countryToFlag(country) {
  const code = String(country || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return '🌍';
  return String.fromCodePoint(...[...code].map((char) => 127397 + char.charCodeAt(0)));
}

function countryLabel(country) {
  const code = String(country || '').trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return 'Unknown';
  try {
    const regionName = new Intl.DisplayNames(['en'], { type: 'region' }).of(code);
    return regionName || code;
  } catch {
    return code;
  }
}

function keyPart(value, maxLen = 80) {
  return String(value || 'na')
    .toLowerCase()
    .replace(/\?.*$/, '')
    .replace(/[^a-z0-9._:-]+/g, '-')
    .replace(/-+/g, '-')
    .slice(0, maxLen) || 'na';
}

function compactWebhookReason(reason) {
  const text = String(reason || '').trim();
  if (!text) return 'N/A';

  const ipRep = text.match(/^ip\s+reputation\s+auto-?block(?:\s*\(score:\s*(\d+)\))?/i)
    || text.match(/^ip\s+rep\s+auto-?block(?:\s*\(score:\s*(\d+)\))?/i);
  if (ipRep) {
    const score = ipRep[1];
    return score ? `IP Rep Block (${score})` : 'IP Rep Block';
  }

  const originReturned = text.match(/^origin returned\s+(\d{3})(?:\s*[—-]\s*|\s+)(.+)$/i);
  if (originReturned) {
    const statusCode = originReturned[1];
    const tail = String(originReturned[2] || '').toLowerCase();
    if (tail.includes('origin down')) return `Origin Down (${statusCode})`;
    return `Origin Error (${statusCode})`;
  }

  return text;
}

function webhookCooldownSeconds(eventType) {
  switch (eventType) {
    case 'SYSTEM_UPDATE':
    case 'DEPLOYED':
      return 90 * 24 * 3600;
    case 'PASSED':
      return 30 * 60;
    case 'FAILED':
      return 10 * 60;
    case 'ERROR':
      return 15 * 60;
    case 'RATE_LIMITED':
      return 15 * 60;
    case 'CHALLENGED':
    case 'EXPIRED':
      return 15 * 60;
    case 'BLOCKED':
    case 'HARD_BLOCKED':
      return 30 * 60;
    case 'ATTACK':
    case 'HONEYPOT':
    case 'HONEYPOT_FORM':
      return 60 * 60;
    case 'BOT_DETECTED':
    case 'BOT_FARM':
    case 'AI_CRAWLER':
      return 30 * 60;
    case 'VPN_BLOCKED':
    case 'COUNTRY_BLOCKED':
      return 60 * 60;
    default:
      return 10 * 60;
  }
}

async function getWebhookCooldownState(env, eventType, details) {
  const cooldown = webhookCooldownSeconds(eventType);
  const isDeployEvent = eventType === 'SYSTEM_UPDATE' || eventType === 'DEPLOYED';
  const event = keyPart(eventType, 24);
  const ip = keyPart(details?.ip || 'na', 64);
  const host = keyPart(details?.host || 'na', 64);
  const deployedVersion = keyPart(details?._deployedVersion || details?._releaseTo || 'na', 64);

  // ERROR/CHALLENGED/PASSED use IP-only key so cross-subdomain visits share cooldown
  const ipOnlyEvents = new Set(['error', 'challenged', 'expired', 'passed', 'failed']);
  const key = isDeployEvent
    ? `shield:webhook:cooldown:${event}:${deployedVersion}`
    : ipOnlyEvents.has(event)
      ? `shield:webhook:cooldown:${event}:${ip}`
      : `shield:webhook:cooldown:${event}:${ip}:${host}`;

  // In-memory check first (instant, no KV read, survives KV write limits)
  const memExpiry = memCooldown.get(key);
  if (memExpiry && memExpiry > Date.now()) {
    return { suppressed: true, key, cooldown };
  }

  // KV check as fallback (covers cross-isolate dedup)
  if (env?.SHIELD_KV) {
    try {
      const exists = await env.SHIELD_KV.get(key);
      if (exists === '1') {
        memCooldown.set(key, Date.now() + cooldown * 1000);
        return { suppressed: true, key, cooldown };
      }
    } catch { /* KV read error — rely on memory only */ }
  }

  return { suppressed: false, key, cooldown };
}

// ─── Discord Webhook (APP-style embed) ───────────────────────────
export async function sendDiscordWebhook(env, eventType, reason, details) {
  const eventLabel = String(eventType || 'EVENT').replace(/_/g, ' ');
  const passedEnabled = String(env?.WEBHOOK_PASSED ?? '1').toLowerCase();
  if (eventType === 'PASSED' && (passedEnabled === '0' || passedEnabled === 'false' || passedEnabled === 'off' || passedEnabled === 'no')) {
    return false;
  }
  const isDeployEvent = eventType === 'DEPLOYED' || eventType === 'SYSTEM_UPDATE';
  const webhookTargets = isDeployEvent
    ? [env?.DISCORD_WEBHOOK_URL_SYSTEM].filter(Boolean)
    : [env?.DISCORD_WEBHOOK_URL, env?.DISCORD_WEBHOOK_URL_2].filter(Boolean);
  if (webhookTargets.length === 0) return;
  if (!DISCORD_WORTHY.has(eventType)) return;
  const cooldownState = await getWebhookCooldownState(env, eventType, details);
  if (cooldownState.suppressed) return false;

  const nowIso = new Date().toISOString();
  const color = WEBHOOK_COLORS[eventType] || 0x5865F2;
  const score = Number(details.threatScore || 0);
  const severity = severityLabel(score);
  const bar = threatBar(score);
  const meta = eventMeta(eventType);
  const isBad = ['BLOCKED', 'HARD_BLOCKED', 'HONEYPOT', 'FAILED', 'ATTACK', 'SUSPENDED', 'BOT_FARM', 'HONEYPOT_FORM'].includes(eventType);
  const isGood = eventType === 'PASSED';
  const isError = eventType === 'ERROR';
  const flags = triggerFlags(details);
  const statusBadge = isDeployEvent ? '🟢 LIVE' : isError ? '🟠 ERROR' : isGood ? '🟢 ALLOWED' : isBad ? '🔴 BLOCKED' : '🟡 CHALLENGED';
  const displayReason = compactWebhookReason(reason);

  // Count how many detections triggered
  const attackFlagCount = Array.isArray(details._attackFlags) ? details._attackFlags.length : 0;
  const detectionCount = [
    details._suspicious,
    details._headless,
    details._vpn,
    details._aiCrawler,
    details._ddosSuspect,
    details._spam,
    details._isBotFarm,
    details._fpSpam,
    details._fpHardBlocked,
    details._requestSmugglingSignal,
    details._commandLineClient,
    details._dataCrawlerUa,
    details._proxyHeaderAnomaly,
    details._longUrlSignal,
    details._pathSpray,
    details._nonGetBurst,
    Number(details._headerCount || 0) > 48,
    Number(details._cookieHeaderLength || 0) > 2500,
  ].filter(Boolean).length + attackFlagCount;

  // ANSI helpers for Discord ```ansi blocks
  const A = {
    red: '\u001b[2;31m', green: '\u001b[2;32m', yellow: '\u001b[2;33m',
    blue: '\u001b[2;34m', cyan: '\u001b[2;36m', white: '\u001b[0m',
    bold: '\u001b[1m', gray: '\u001b[2;30m', reset: '\u001b[0m',
    bRed: '\u001b[1;31m', bGreen: '\u001b[1;32m', bYellow: '\u001b[1;33m',
    bCyan: '\u001b[1;36m', bWhite: '\u001b[1;37m',
  };
  const toInt = (value, fallback) => {
    const parsed = Number.parseInt(String(value ?? ''), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };
  const scanPairWidth = toInt(env?.WEBHOOK_SCAN_PAIR_WIDTH, 18);
  const scanSectionWidth = toInt(env?.WEBHOOK_SCAN_SECTION_WIDTH, 35);
  const scanFactorsGap = Math.max(3, toInt(env?.WEBHOOK_SCAN_FACTORS_GAP, 4));
  // Edge status
  const hasAttack = (details._attackFlags?.length > 0);
  const edgeOk = eventType !== 'ERROR';
  const wafOk = !hasAttack;

  // Score breakdown
  const baseThreat = Number(details._baseThreatScore || 0);
  const ipRepScore = Number(details._ipRepScore || 0);
  const escalation = details._escalation || 'N/A';
  const scoreDelta = score - baseThreat;

  // ── Description ──
  const description = isDeployEvent
    ? [
        '```ansi',
        `${A.bCyan}${eventType === 'DEPLOYED' ? '◆ SOURCE UPDATE' : '◆ SYSTEM UPDATE'}${A.reset}`,
        `${A.white}Release: ${A.bWhite}${clip(String(details._releaseFrom || 'initial') + ' → ' + String(details._releaseTo || 'latest'), 60)}${A.reset}`,
        `${A.white}Build:   ${A.gray}${clip(shortVersionId(details._previousDeployedVersion || 'none') + ' → ' + shortVersionId(details._deployedVersion || 'latest'), 40)}${A.reset}`,
        `${A.white}Source:  ${A.gray}${clip(String(details._sourceRevision || 'unknown'), 40)}${A.reset}`,
        '```',
      ].join('\n')
    : '';

  // ── Fields ──
  const fields = [];

  // Top summary (clean side-by-side blocks)
  const countryCode = String(details.country || '').trim().toUpperCase();
  const locValue = /^[A-Z]{2}$/.test(countryCode)
    ? `${countryLabel(details.country)} (${countryCode})`
    : countryLabel(details.country);
  const requestLines = [
    `${A.yellow}•${A.reset} ${A.white}IP Address${A.reset}       ${A.bCyan}${clip(details.ip || 'N/A', 24)}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Host Name${A.reset}        ${A.bCyan}${clip(details.host || 'N/A', 24)}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Request Path${A.reset}     ${A.cyan}${clip(details.path || '/', 24)}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Location${A.reset}         ${A.white}${clip(locValue, 24)}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}ASN Organization${A.reset} ${A.gray}${clip((details.asOrg && details.asOrg !== 'N/A') ? String(details.asOrg) : 'Unknown', 24)}${A.reset}`,
  ];
  const threatLines = [
    `${A.yellow}•${A.reset} ${A.white}Threat Score${A.reset}     ${score >= 60 ? A.bRed : score >= 30 ? A.bYellow : A.bGreen}${score}/100${A.reset} ${A.gray}${severity}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Score Flow${A.reset}       ${A.white}${baseThreat} → ${score}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Reputation Delta${A.reset} ${scoreDelta >= 0 ? A.green : A.red}${scoreDelta >= 0 ? '+' : ''}${scoreDelta}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Threat Bar${A.reset}       ${A.white}${bar}${A.reset}`,
    `${A.yellow}•${A.reset} ${A.white}Client Type${A.reset}      ${A.cyan}${clip(details._clientType || 'unknown', 20)}${A.reset}`,
  ];

  fields.push({
    name: '🧾 Request',
    value: '```ansi\n' + requestLines.join('\n') + '\n```',
    inline: false,
  });
  fields.push({
    name: '🎯 Threat',
    value: '```ansi\n' + threatLines.join('\n') + '\n```',
    inline: false,
  });

  // System Status — ANSI colored
  fields.push({
    name: '⚡ Infrastructure',
    value: '```ansi\n'
      + `${edgeOk ? A.bGreen : A.bRed}▣${A.reset} ${A.white}Gateway${A.reset}   ${edgeOk ? `${A.green}Online` : `${A.red}Error`}${A.reset}\n`
      + `${wafOk ? A.bGreen : A.bRed}▣${A.reset} ${A.white}WAF${A.reset}       ${wafOk ? `${A.green}Clean` : `${A.red}Attack`}${A.reset}\n`
      + `${detectionCount === 0 ? A.bGreen : detectionCount < 3 ? A.bYellow : A.bRed}▣${A.reset} ${A.white}Shield${A.reset}    ${detectionCount === 0 ? `${A.green}Clear` : `${A.yellow}${detectionCount} hits`}${A.reset}\n`
      + `${A.bGreen}▣${A.reset} ${A.white}CDN${A.reset}       ${A.green}Online${A.reset}\n`
      + '```',
    inline: true,
  });

  // Request metadata
  fields.push({
    name: '🔒 Connection',
    value: '```ansi\n'
      + `${A.white}TLS${A.reset}    ${A.bCyan}${details.tlsVersion || 'N/A'}${A.reset}\n`
      + `${A.white}HTTP${A.reset}   ${A.bCyan}${details.httpVersion || 'N/A'}${A.reset}\n`
      + `${A.white}ASN${A.reset}    ${A.gray}${clip(details.asn || 'N/A', 12)}${A.reset}\n`
      + `${A.white}Ray${A.reset}    ${A.gray}${clip(details.rayId || 'N/A', 16)}${A.reset}\n`
      + '```',
    inline: true,
  });

  // Security Scan + Factors (side-by-side in one block)
  const visibleLen = (text) => String(text || '').replace(/\u001b\[[0-9;]*m/g, '').length;
  const ansiPadEnd = (text, width) => {
    const value = String(text || '');
    const pad = Math.max(0, width - visibleLen(value));
    return value + ' '.repeat(pad);
  };

  if (!isDeployEvent) {
    const hps = Number(details._headerPresenceScore || 0);
    const tlsS = Number(details._tlsScore || 0);
    const patS = Number(details._patternScore || 0);
    const ipRate = Number(details._ipRate || 0);
    const headerCount = Number(details._headerCount || 0);
    const cookieHeaderLength = Number(details._cookieHeaderLength || 0);
    const mark = (on) => on ? `${A.bRed}■${A.reset}` : `${A.green}□${A.reset}`;
    const scanItem = (label, on) => `${mark(on)} ${(on ? A.white : A.gray)}${label}${A.reset}`;
    const scanLines = [
      `${ansiPadEnd(scanItem('Bot', details._suspicious), scanPairWidth)} ${scanItem('Headless', details._headless)}`,
      `${ansiPadEnd(scanItem('VPN/Proxy', details._vpn), scanPairWidth)} ${scanItem('AI Crawl', details._aiCrawler)}`,
      `${ansiPadEnd(scanItem('DDoS', details._ddosSuspect), scanPairWidth)} ${scanItem('Rate Lim', details._spam)}`,
      `${ansiPadEnd(scanItem('Bot Farm', details._isBotFarm), scanPairWidth)} ${scanItem('Attack', hasAttack)}`,
      `${ansiPadEnd(scanItem('Smuggle', details._requestSmugglingSignal), scanPairWidth)} ${scanItem('Cookie Abuse', Number(details._cookieHeaderLength || 0) > 2500)}`,
      `${ansiPadEnd(scanItem('Cmd Client', details._commandLineClient), scanPairWidth)} ${scanItem('Data Crawler', details._dataCrawlerUa)}`,
      `${ansiPadEnd(scanItem('Proxy Hdr', details._proxyHeaderAnomaly), scanPairWidth)} ${scanItem('Long URL', details._longUrlSignal)}`,
      `${ansiPadEnd(scanItem('ProtoPoll', details._prototypePollution), scanPairWidth)} ${scanItem('Deserialize', details._deserializationProbe)}`,
      `${ansiPadEnd(scanItem('Open Redirect', details._openRedirectProbe), scanPairWidth)} ${scanItem('Hdr Flood', Number(details._headerCount || 0) > 48)}`,
    ];

    const factorLines = [
      `${A.white}Headers${A.reset}  ${hps >= 6 ? A.green : A.yellow}${hps}/8${A.reset}`,
      ipRepScore !== 0
        ? `${A.white}IP Reputation${A.reset}  ${ipRepScore > 50 ? A.bRed : A.yellow}${ipRepScore}${A.reset}`
        : `${A.white}IP Reputation${A.reset}  ${A.green}0${A.reset}`,
      ipRate > 0
        ? `${A.white}Rate${A.reset}  ${ipRate > 10 ? A.bRed : A.cyan}${ipRate}/10s${A.reset}`
        : `${A.white}Rate${A.reset}  ${A.green}0/10s${A.reset}`,
      tlsS > 0
        ? `${A.white}TLS/Pattern${A.reset}  ${A.yellow}+${tlsS}${A.reset}`
        : (patS > 0 ? `${A.white}TLS/Pattern${A.reset}  ${A.yellow}+${patS}${A.reset}` : `${A.white}TLS/Pattern${A.reset}  ${A.green}0${A.reset}`),
      `${A.white}Header Count${A.reset}  ${headerCount > 48 ? A.bRed : A.cyan}${headerCount}${A.reset}`,
      `${A.white}Cookie Len${A.reset}  ${cookieHeaderLength > 2500 ? A.bRed : A.cyan}${cookieHeaderLength}${A.reset}`,
    ];

    const rowCount = Math.max(scanLines.length, factorLines.length);
    const combinedLines = [];
    for (let i = 0; i < rowCount; i++) {
      const left = scanLines[i] || '';
      const right = factorLines[i] || '';
      combinedLines.push(ansiPadEnd(left, scanSectionWidth) + ' '.repeat(scanFactorsGap) + right);
    }
    fields.push({
      name: `🔍 Scan Results  ·  ${detectionCount} detection${detectionCount !== 1 ? 's' : ''}  ·  📊 Factors`,
      value: '```ansi\n' + combinedLines.join('\n') + '\n```',
      inline: false,
    });
  } else {
    const mark = (on) => on ? `${A.bRed}■${A.reset}` : `${A.green}□${A.reset}`;
    const scanItem = (label, on) => `${mark(on)} ${(on ? A.white : A.gray)}${label}${A.reset}`;
    const scanOnly = [
      `${ansiPadEnd(scanItem('Bot', details._suspicious), scanPairWidth)} ${scanItem('Headless', details._headless)}`,
      `${ansiPadEnd(scanItem('VPN/Proxy', details._vpn), scanPairWidth)} ${scanItem('AI Crawl', details._aiCrawler)}`,
      `${ansiPadEnd(scanItem('DDoS', details._ddosSuspect), scanPairWidth)} ${scanItem('Rate Lim', details._spam)}`,
      `${ansiPadEnd(scanItem('Bot Farm', details._isBotFarm), scanPairWidth)} ${scanItem('Attack', hasAttack)}`,
      `${ansiPadEnd(scanItem('Smuggle', details._requestSmugglingSignal), scanPairWidth)} ${scanItem('Cookie Abuse', Number(details._cookieHeaderLength || 0) > 2500)}`,
      `${ansiPadEnd(scanItem('Cmd Client', details._commandLineClient), scanPairWidth)} ${scanItem('Data Crawler', details._dataCrawlerUa)}`,
      `${ansiPadEnd(scanItem('Proxy Hdr', details._proxyHeaderAnomaly), scanPairWidth)} ${scanItem('Long URL', details._longUrlSignal)}`,
      `${ansiPadEnd(scanItem('ProtoPoll', details._prototypePollution), scanPairWidth)} ${scanItem('Deserialize', details._deserializationProbe)}`,
      `${ansiPadEnd(scanItem('Open Redirect', details._openRedirectProbe), scanPairWidth)} ${scanItem('Hdr Flood', Number(details._headerCount || 0) > 48)}`,
    ];
    fields.push({
      name: `🔍 Scan Results  ·  ${detectionCount} detection${detectionCount !== 1 ? 's' : ''}`,
      value: '```ansi\n' + scanOnly.join('\n') + '\n```',
      inline: false,
    });
  }

  // Bottom details (Status + Reason + Signals + Penalty in one spaced block)
  if (!isDeployEvent) {
    const maxFlagLines = 4;
    const normalizedFlags = flags.map((f) => clip(String(f || '').replace(/^\s*•\s*/g, ''), 20));
    const visibleFlags = normalizedFlags.slice(0, maxFlagLines).map((f) => `• ${f}`);
    if (normalizedFlags.length > maxFlagLines) {
      visibleFlags.push(`• +${normalizedFlags.length - maxFlagLines} more`);
    }

    const leftLines = [
      `${statusBadge}`,
      `💬 ${clip(displayReason, 20)}`,
      ...(visibleFlags.length > 0 ? visibleFlags : ['• None']),
    ];

    const untilPretty = details._penaltyPermanent
      ? 'permanent'
      : (() => {
          try {
            const d = new Date(details._penaltyUntil);
            if (isNaN(d.getTime())) return String(details._penaltyUntil || 'N/A');
            const diffMs = Math.max(0, d.getTime() - Date.now());
            const mins = Math.round(diffMs / 60000);
            if (mins < 1) return 'in <1 minute';
            if (mins < 60) return `in ${mins} minute${mins === 1 ? '' : 's'}`;
            const hours = Math.round(mins / 60);
            return `in ${hours} hour${hours === 1 ? '' : 's'}`;
          } catch { return String(details._penaltyUntil || 'N/A'); }
        })();

    const rightLines = [
      `Duration: ${clip(details._penaltyLabel || 'none', 20)}`,
      `Expires: ${clip(details._penaltyLabel ? untilPretty : 'N/A', 20)}`,
    ];

    const bottomLines = [];
    const leftWidth = 24;
    const rowGap = '     ';
    const rows = Math.max(leftLines.length, rightLines.length);
    bottomLines.push(`${A.bCyan}Stats${A.reset}`.padEnd(leftWidth, ' ') + rowGap + `${A.bYellow}Penalty${A.reset}`);
    for (let i = 0; i < rows; i++) {
      const left = clip(leftLines[i] || '', leftWidth).padEnd(leftWidth, ' ');
      const right = clip(rightLines[i] || '', 28);
      bottomLines.push(left + rowGap + right);
    }

    fields.push({
      name: '🛰️ Server Logs',
      value: '```ansi\n' + bottomLines.join('\n') + '\n```',
      inline: false,
    });
  }

  const dashboardUrl = String(env?.SHIELD_DASHBOARD_URL || '').trim();
  const eventsUrl = String(env?.SHIELD_EVENTS_URL || '').trim();
  const servicesUrl = String(env?.SHIELD_SERVICES_URL || '').trim();
  const pingUrl = String(env?.SHIELD_PING_URL || '').trim();

  const buttons = [];
  if (dashboardUrl) buttons.push({ type: 2, style: 5, label: 'Refresh', url: dashboardUrl });
  if (eventsUrl) buttons.push({ type: 2, style: 5, label: 'Details', url: eventsUrl });
  if (servicesUrl) buttons.push({ type: 2, style: 5, label: 'Services', url: servicesUrl });
  if (pingUrl) buttons.push({ type: 2, style: 5, label: 'Ping All', url: pingUrl });

  const logoUrl = String(env?.SHIELD_LOGO_URL || DEFAULT_LOGO_URL);

  // Footer parts — include penalty info
  const footerParts = ['Ryzeon Shield', eventLabel];
  if (details._penaltyLabel) footerParts.push('⚖️ ' + details._penaltyLabel);
  footerParts.push('Ray ' + (details.rayId || 'N/A'));

  const payload = {
    username: 'Ryzeon Shield',
    avatar_url: logoUrl,
    embeds: [{
      color,
      title: `${meta.icon} Ryzeon Shield — ${meta.banner}`,
      description,
      fields,
      footer: {
        text: footerParts.join(' • '),
        icon_url: logoUrl,
      },
      timestamp: nowIso,
    }],
    ...(buttons.length ? { components: [{ type: 1, components: buttons.slice(0, 5) }] } : {}),
  };

  try {
    const sends = await Promise.allSettled(
      webhookTargets.map((url) => fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      }))
    );
    const delivered = sends.some((r) => r.status === 'fulfilled' && r.value?.ok);
    if (cooldownState.key && cooldownState.cooldown > 0) {
      // Always set in-memory cooldown (works even when KV writes are exhausted)
      memCooldown.set(cooldownState.key, Date.now() + cooldownState.cooldown * 1000);
      memCooldownCleanup();
      // Best-effort KV write for cross-isolate dedup
      if (delivered && env?.SHIELD_KV) {
        try {
          await env.SHIELD_KV.put(cooldownState.key, '1', { expirationTtl: cooldownState.cooldown });
        } catch { /* KV write limit — in-memory cooldown still active */ }
      }
    }
    return delivered;
  } catch {
    return false;
  }
}

// ─── External Logging (MySQL/API) ────────────────────────────────
export async function sendExternalLog(env, eventType, reason, details) {
  const logUrl = env?.LOG_ENDPOINT;
  const logKey = env?.LOG_API_KEY || '';
  if (!logUrl) return;

  const payload = {
    event: eventType, reason,
    ip: details.ip, country: details.country,
    host: details.host, path: details.path,
    method: details.method, ua: details.ua,
    referer: details.referer, asOrg: details.asOrg,
    asn: details.asn, colo: details.colo,
    rayId: details.rayId, threatScore: details.threatScore,
    tlsVersion: details.tlsVersion, httpVersion: details.httpVersion,
    attackFlags: details._attackFlags || [],
    timestamp: details.utcTime,
  };

  try {
    await fetch(logUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(logKey ? { authorization: 'Bearer ' + logKey } : {}),
      },
      body: JSON.stringify(payload),
    });
  } catch {}
}

// ─── D1 Database Logging ─────────────────────────────────────────
export async function logToD1(env, eventType, reason, details) {
  if (!env?.SHIELD_DB) return;
  try {
    await env.SHIELD_DB.prepare(
      'INSERT INTO events (event, reason, ip, country, host, path, method, ua, referer, as_org, asn, colo, ray_id, threat_score, tls_version, http_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      eventType, reason, details.ip, details.country,
      details.host, details.path, details.method, details.ua,
      details.referer, details.asOrg, details.asn, details.colo,
      details.rayId, details.threatScore || 0,
      details.tlsVersion, details.httpVersion, details.utcTime,
    ).run();
  } catch {}
}

// ─── D1 Error Logging ────────────────────────────────────────────
export async function logErrorToD1(env, errorMessage, errorStack, details) {
  if (!env?.SHIELD_DB) return;
  try {
    await env.SHIELD_DB.prepare(
      'INSERT INTO events (event, reason, ip, country, host, path, method, ua, referer, as_org, asn, colo, ray_id, threat_score, tls_version, http_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      'ERROR',
      (errorMessage + (errorStack ? ' | ' + errorStack.slice(0, 300) : '')),
      details?.ip || 'N/A', details?.country || 'N/A',
      details?.host || 'N/A', details?.path || 'N/A',
      details?.method || 'N/A', details?.ua || 'N/A',
      details?.referer || 'N/A', details?.asOrg || 'N/A',
      details?.asn || 'N/A', details?.colo || 'N/A',
      details?.rayId || 'N/A', 0,
      details?.tlsVersion || 'N/A', details?.httpVersion || 'N/A',
      new Date().toISOString(),
    ).run();
  } catch {}
}

// ─── R2 Snapshot Storage ─────────────────────────────────────────
export async function saveToR2(env, eventType, details) {
  if (!env?.SHIELD_R2) return;
  if (!['BLOCKED', 'HARD_BLOCKED', 'HONEYPOT', 'ATTACK'].includes(eventType)) return;
  try {
    const day = new Date().toISOString().slice(0, 10);
    const key = day + '/' + eventType + '/' + (details.rayId || crypto.randomUUID()) + '.json';
    const snapshot = {
      event: eventType,
      ip: details.ip, country: details.country,
      host: details.host, path: details.path,
      method: details.method, ua: details.ua,
      referer: details.referer, asOrg: details.asOrg,
      asn: details.asn, colo: details.colo,
      rayId: details.rayId, threatScore: details.threatScore,
      tlsVersion: details.tlsVersion, httpVersion: details.httpVersion,
      acceptLanguage: details.acceptLanguage,
      attackFlags: details._attackFlags || [],
      timestamp: details.utcTime,
    };
    await env.SHIELD_R2.put(key, JSON.stringify(snapshot, null, 2), {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: { event: eventType, ip: details.ip, country: details.country },
    });
  } catch {}
}

// ─── KV Analytics ────────────────────────────────────────────────
export async function incrementKvStat(env, key) {
  if (!env?.SHIELD_KV) return;
  try {
    const day = new Date().toISOString().slice(0, 10);
    const k = 'stats:' + day + ':' + key;
    const cur = parseInt((await env.SHIELD_KV.get(k)) || '0', 10);
    await env.SHIELD_KV.put(k, String(cur + 1), { expirationTtl: 86400 * 30 });
  } catch {}
}

// ─── Deployment Event ────────────────────────────────────────────
export async function emitDeploymentEventIfNeeded(env, details) {
  const meta = env?.SHIELD_VERSION_METADATA || {};
  const stableCandidates = [
    meta?.id,
    meta?.version_id,
    meta?.deployment_id,
    meta?.tag,
    meta?.version,
    meta?.name,
    env?.SHIELD_VERSION,
  ];
  const stableVersion = stableCandidates.find((v) => typeof v === 'string' && v.trim().length > 0) || null;
  const version = String(stableVersion || '').trim();
  if (!version) return;

  if (deploymentEventSent && deploymentEventVersion === version) return;

  const sourceCandidates = [
    env?.SHIELD_SOURCE_REV,
    env?.SOURCE_VERSION,
    env?.GITHUB_SHA,
    env?.CF_PAGES_COMMIT_SHA,
    meta?.source,
    meta?.git_sha,
    meta?.commit,
  ];
  const sourceRevision = sourceCandidates.find((v) => typeof v === 'string' && v.trim().length > 0) || null;
  const sourceLabel = sourceRevision ? shortVersionId(sourceRevision) : 'unknown';

  const baseRelease = String(env?.SHIELD_RELEASE_BASE || 'v4.0.0').trim();
  const bumpTypeRaw = String(env?.SHIELD_RELEASE_BUMP || 'patch').trim().toLowerCase();
  const bumpType = ['major', 'minor', 'patch'].includes(bumpTypeRaw) ? bumpTypeRaw : 'patch';

  let prev = null;
  let previousRelease = null;
  let currentRelease = parseRelease(baseRelease)
    ? (baseRelease.startsWith('v') ? baseRelease : `v${baseRelease}`)
    : 'v4.0.0';

  const hasKv = !!env?.SHIELD_KV;

  const key = 'shield:meta:deployed_version';
  const releaseKey = 'shield:meta:deployed_release';
  const announcedVersionKey = `shield:meta:deploy_announced:${version}`;

  if (hasKv) {
    const alreadyAnnounced = await env.SHIELD_KV.get(announcedVersionKey);
    if (alreadyAnnounced === '1') {
      deploymentEventSent = true;
      deploymentEventVersion = version;
      return;
    }

    prev = await env.SHIELD_KV.get(key);
    if (prev === version) {
      await env.SHIELD_KV.put(announcedVersionKey, '1', { expirationTtl: 90 * 24 * 3600 });
      deploymentEventSent = true;
      deploymentEventVersion = version;
      return;
    }

    const prevMappedRelease = prev ? await env.SHIELD_KV.get(`shield:meta:release_by_worker:${prev}`) : null;
    const latestRelease = await env.SHIELD_KV.get(releaseKey);
    previousRelease = prevMappedRelease || latestRelease || null;
    currentRelease = previousRelease
      ? bumpRelease(previousRelease, bumpType)
      : currentRelease;
  } else if (env?.SHIELD_DB) {
    try {
      const marker = `[worker:${version}]`;
      const existing = await env.SHIELD_DB.prepare(
        "SELECT id FROM events WHERE event IN ('SYSTEM_UPDATE','DEPLOYED') AND reason LIKE ? ORDER BY id DESC LIMIT 1"
      ).bind(`%${marker}%`).first();
      if (existing) {
        deploymentEventSent = true;
        deploymentEventVersion = version;
        return;
      }
    } catch {}
  }

  const workerMarker = prev
    ? `[worker:${shortVersionId(prev)}->${shortVersionId(version)}]`
    : `[worker:${shortVersionId(version)}]`;
  const reason = prev
    ? `Source updated and deployed: ${currentRelease} [source:${sourceLabel}] ${workerMarker} [worker:${version}]`
    : `Source updated and deployed: ${currentRelease} [source:${sourceLabel}] ${workerMarker} [worker:${version}]`;

  const deployDetails = {
    ...details,
    threatScore: 0,
    _clientType: 'system',
    _deployedVersion: version,
    _previousDeployedVersion: prev || null,
    _releaseFrom: previousRelease || 'initial',
    _releaseTo: currentRelease,
    _sourceRevision: sourceRevision || 'unknown',
  };

  const delivered = await sendDiscordWebhook(env, 'DEPLOYED', reason, deployDetails);

  if (!delivered) return;

  if (env?.SHIELD_DB) {
    try {
      await logToD1(env, 'DEPLOYED', reason, deployDetails);
    } catch {}
  }

  if (hasKv) {
    try {
      await env.SHIELD_KV.put(key, version);
      await env.SHIELD_KV.put(releaseKey, currentRelease);
      await env.SHIELD_KV.put(`shield:meta:release_by_worker:${version}`, currentRelease);
      await env.SHIELD_KV.put(announcedVersionKey, '1', { expirationTtl: 90 * 24 * 3600 });
    } catch {}
  }

  deploymentEventSent = true;
  deploymentEventVersion = version;
}
