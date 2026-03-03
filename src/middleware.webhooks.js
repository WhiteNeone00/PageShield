/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Webhooks, Logging & Analytics
   Discord embeds, D1 logging, R2 snapshots, KV stats
   ═══════════════════════════════════════════════════════════════════ */

import { WEBHOOK_COLORS, DISCORD_WORTHY } from './core.config.js';
import { clip, compactMiddle, severityLabel, threatBar } from './core.utils.js';

// ─── Deployment Event State ──────────────────────────────────────
let deploymentEventSent = false;

// ─── Trigger Flags ───────────────────────────────────────────────
function triggerFlags(details) {
  const flags = [];
  if (details._suspicious) flags.push('\uD83D\uDEA8 Bot/Suspicious');
  if (details._headless) flags.push('\uD83E\uDD16 Headless Browser');
  if (details._vpn) flags.push('\uD83D\uDD12 VPN/Proxy/DC');
  if (details._aiCrawler) flags.push('\uD83E\uDDE0 AI Crawler');
  if (details._ddosSuspect) flags.push('\uD83C\uDF0A DDoS/Burst Pattern');
  if (details._spam) flags.push('\u26A1 Rate Limited');
  if (details._attackFlags?.length) flags.push('\uD83D\uDEE1\uFE0F ' + details._attackFlags.join(', '));
  if (details._clientType && details._clientType !== 'unknown') flags.push('\uD83E\uDDEC Type: ' + details._clientType);
  return flags;
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

function webhookCooldownSeconds(eventType) {
  switch (eventType) {
    case 'SYSTEM_UPDATE':
    case 'DEPLOYED':
      return 90 * 24 * 3600;
    case 'PASSED':
      return 15 * 60;
    case 'FAILED':
      return 120;
    case 'ERROR':
      return 60;
    case 'RATE_LIMITED':
      return 45;
    case 'BLOCKED':
    case 'HARD_BLOCKED':
    case 'ATTACK':
    case 'HONEYPOT':
    case 'HONEYPOT_FORM':
      return 20;
    default:
      return 30;
  }
}

async function getWebhookCooldownState(env, eventType, details) {
  if (!env?.SHIELD_KV) return { suppressed: false, key: '', cooldown: 0 };

  const cooldown = webhookCooldownSeconds(eventType);
  const isDeployEvent = eventType === 'SYSTEM_UPDATE' || eventType === 'DEPLOYED';
  const event = keyPart(eventType, 24);
  const ip = keyPart(details?.ip || 'na', 64);
  const fp = keyPart(details?.fpHash || 'na', 64);
  const host = keyPart(details?.host || 'na', 64);
  const path = keyPart(details?.path || '/', 64);
  const deployedVersion = keyPart(details?._deployedVersion || details?._releaseTo || 'na', 64);

  const key = isDeployEvent
    ? `shield:webhook:cooldown:${event}:${deployedVersion}`
    : `shield:webhook:cooldown:${event}:${ip}:${fp}:${host}:${path}`;

  const exists = await env.SHIELD_KV.get(key);
  if (exists === '1') return { suppressed: true, key, cooldown };
  return { suppressed: false, key, cooldown };
}

// ─── Discord Webhook (APP-style embed) ───────────────────────────
export async function sendDiscordWebhook(env, eventType, reason, details) {
  const eventLabel = String(eventType || 'EVENT').replace(/_/g, ' ');
  const isDeployEvent = eventType === 'DEPLOYED' || eventType === 'SYSTEM_UPDATE';
  const webhookTargets = isDeployEvent
    ? [env?.DISCORD_WEBHOOK_URL_SYSTEM].filter(Boolean)
    : [env?.DISCORD_WEBHOOK_URL, env?.DISCORD_WEBHOOK_URL_2].filter(Boolean);
  if (webhookTargets.length === 0) return;
  if (!DISCORD_WORTHY.has(eventType)) return;
  const cooldownState = await getWebhookCooldownState(env, eventType, details);
  if (cooldownState.suppressed) return false;

  const nowIso = new Date().toISOString();
  const nowUnix = Math.floor(Date.now() / 1000);
  const updatedPretty = new Intl.DateTimeFormat('en-US', {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZone: 'UTC',
  }).format(new Date());
  const color = WEBHOOK_COLORS[eventType] || 0x5865F2;
  const score = Number(details.threatScore || 0);
  const severity = severityLabel(score);
  const bar = threatBar(score);
  const meta = eventMeta(eventType);
  const isBad = ['BLOCKED', 'HARD_BLOCKED', 'HONEYPOT', 'FAILED', 'ATTACK', 'SUSPENDED', 'BOT_FARM', 'HONEYPOT_FORM'].includes(eventType);
  const isGood = eventType === 'PASSED';
  const hostCompact = compactMiddle(details.host || 'N/A', 38);
  const pathCompact = compactMiddle(details.path || '/', 56);
  const flags = triggerFlags(details);
  const statusBadge = isDeployEvent ? '🟢 LIVE' : isGood ? '🟢 ALLOWED' : isBad ? '🔴 BLOCKED' : '🟡 CHALLENGED';

  const statusRow = (label, value) => label.padEnd(15, ' ') + '  ' + value;

  const secStatusLines = [
    statusRow('Bot Detection', details._suspicious ? '🔴 Flagged' : '🟢 Clean'),
    statusRow('Headless', details._headless ? '🔴 Detected' : '🟢 None'),
    statusRow('VPN/Proxy', details._vpn ? '🟡 Yes' : '🟢 No'),
    statusRow('AI Crawler', details._aiCrawler ? '🔴 Yes' : '🟢 No'),
    statusRow('DDoS Pattern', details._ddosSuspect ? '🔴 Yes' : '🟢 No'),
    statusRow('Rate Limit', details._spam ? '🔴 Hit' : '🟢 OK'),
    statusRow('Attack Vectors', (details._attackFlags?.length) ? '🔴 ' + clip(details._attackFlags.join(','), 40) : '🟢 None'),
  ];

  const edgeStatus = eventType === 'ERROR' ? '🔴' : '🟢';
  const wafStatus = isBad ? '🟡' : '🟢';

  const fields = [
    {
      name: '⚡ API / Edge Status',
      value: '```\n'
        + '├─ API Gateway:  🟢\n'
        + '├─ WAF Engine:   🟡\n'
        + '└─ CDN Edge:     🟢\n'
        + '```',
      inline: true,
    },
    {
      name: '🛡️ Request Route',
      value: '```\n'
        + 'Host: ' + clip(details.host || hostCompact, 48) + '\n'
        + 'Path: ' + clip(details.path || pathCompact, 56) + '\n'
        + 'IP: ' + clip(details.ip || 'N/A', 26) + '\n'
        + 'ASN: ' + clip(
            (details.asOrg && details.asOrg !== 'N/A') ? String(details.asOrg) : 'Unknown Network',
            56
          ) + '\n'
        + '```',
      inline: true,
    },
    {
      name: '⚡ Security Status',
      value: '```\n' + secStatusLines.join('\n') + '\n```',
      inline: false,
    },
    {
      name: '⏱️ Uptime / Version',
      value: '```\n'
        + 'Updated: ' + updatedPretty + ' UTC' + '\n'
        + 'Version: ' + clip(String(details._releaseTo || details._deployedVersion || 'v4.x.x'), 24) + '\n'
        + '```',
      inline: true,
    },
  ];

  fields.push({
    name: '⚠️ Detection Signals',
    value: '```\n'
      + '• 🚨 Bot/Suspicious: ' + (details._suspicious ? 'yes' : 'no') + '\n'
      + '• 🧬 Type: ' + clip(details._clientType || 'unknown', 18) + '\n'
      + '• 🛰️ Signal: ' + clip(flags[0] || 'none', 58) + '\n'
      + '```',
    inline: true,
  });


  const description = isDeployEvent
    ? [
        '📊 **System Status & Health Check**',
        `${meta.icon} **Ryzeon Shield • SYSTEM UPDATE**`,
        `**Release:** \`${clip(String(details._releaseFrom || 'initial') + ' → ' + String(details._releaseTo || 'latest'), 72)}\``,
      `**Build:** \`${clip(shortVersionId(details._previousDeployedVersion || 'none') + ' → ' + shortVersionId(details._deployedVersion || 'latest'), 40)}\``,
      ].join('\n')
    : [
        '📊 **System Status & Health Check**',
        '```',
        `Location: ${countryLabel(details.country)} ${countryToFlag(details.country)}`,
        `Status: ${statusBadge}`,
        `Score: ${score}/100`,
        `Threat: ${bar}`,
        `Reason: ${clip(reason, 140)}`,
        '```',
      ].join('\n');

  const dashboardUrl = String(env?.SHIELD_DASHBOARD_URL || '').trim();
  const eventsUrl = String(env?.SHIELD_EVENTS_URL || '').trim();
  const servicesUrl = String(env?.SHIELD_SERVICES_URL || '').trim();
  const pingUrl = String(env?.SHIELD_PING_URL || '').trim();

  const buttons = [];
  if (dashboardUrl) buttons.push({ type: 2, style: 5, label: 'Refresh', url: dashboardUrl });
  if (eventsUrl) buttons.push({ type: 2, style: 5, label: 'Details', url: eventsUrl });
  if (servicesUrl) buttons.push({ type: 2, style: 5, label: 'Services', url: servicesUrl });
  if (pingUrl) buttons.push({ type: 2, style: 5, label: 'Ping All', url: pingUrl });

  const logoUrl = 'https://cdn.ryzeon.wtf/logo.webp';

  const payload = {
    username: 'Ryzeon Shield',
    avatar_url: logoUrl,
    embeds: [{
      color,
      title: 'Ryzeon Shield Logs',
      description,
      fields,
      footer: {
        text: 'Ryzeon Shield v3 • ' + eventLabel + ' • Ray ' + (details.rayId || 'N/A'),
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
    if (delivered && env?.SHIELD_KV && cooldownState.key && cooldownState.cooldown > 0) {
      await env.SHIELD_KV.put(cooldownState.key, '1', { expirationTtl: cooldownState.cooldown });
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
  if (deploymentEventSent) return;
  if (!env?.SHIELD_KV) return;

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

  const key = 'shield:meta:deployed_version';
  const releaseKey = 'shield:meta:deployed_release';
  const announcedVersionKey = `shield:meta:deploy_announced:${version}`;

  const alreadyAnnounced = await env.SHIELD_KV.get(announcedVersionKey);
  if (alreadyAnnounced === '1') {
    deploymentEventSent = true;
    return;
  }

  const prev = await env.SHIELD_KV.get(key);
  if (prev === version) {
    await env.SHIELD_KV.put(announcedVersionKey, '1', { expirationTtl: 90 * 24 * 3600 });
    deploymentEventSent = true;
    return;
  }

  const baseRelease = String(env?.SHIELD_RELEASE_BASE || 'v4.0.0').trim();
  const bumpTypeRaw = String(env?.SHIELD_RELEASE_BUMP || 'patch').trim().toLowerCase();
  const bumpType = ['major', 'minor', 'patch'].includes(bumpTypeRaw) ? bumpTypeRaw : 'patch';

  const prevMappedRelease = prev ? await env.SHIELD_KV.get(`shield:meta:release_by_worker:${prev}`) : null;
  const latestRelease = await env.SHIELD_KV.get(releaseKey);
  const previousRelease = prevMappedRelease || latestRelease || null;
  const currentRelease = previousRelease
    ? bumpRelease(previousRelease, bumpType)
    : (parseRelease(baseRelease) ? (baseRelease.startsWith('v') ? baseRelease : `v${baseRelease}`) : 'v4.0.0');

  const reason = prev
    ? `Ryzeon Shield new update deployed successfully: ${currentRelease}`
    : `Ryzeon Shield initial deployment completed: ${currentRelease}`;

  const delivered = await sendDiscordWebhook(env, 'SYSTEM_UPDATE', reason, {
    ...details,
    threatScore: 0,
    _clientType: 'system',
    _deployedVersion: version,
    _previousDeployedVersion: prev || null,
    _releaseFrom: previousRelease || 'initial',
    _releaseTo: currentRelease,
  });

  if (!delivered) return;

  await env.SHIELD_KV.put(key, version);
  await env.SHIELD_KV.put(releaseKey, currentRelease);
  await env.SHIELD_KV.put(`shield:meta:release_by_worker:${version}`, currentRelease);
  await env.SHIELD_KV.put(announcedVersionKey, '1', { expirationTtl: 90 * 24 * 3600 });
  deploymentEventSent = true;
}
