import { normalizeIp, parseIpListPayload, securityHeaders } from './core.utils.js';

const BLACKLIST_KEY = 'remote:blacklisted_ips';
const WHITELIST_EXTRA_KEY = 'shield:whitelist:extra';
const POLICY_KEY = 'shield:config:policy';

const DEFAULT_POLICY = {
  protectEnabled: true,
  rateLimitEnabled: true,
  attackBlockEnabled: true,
  honeypotEnabled: true,
  aiCrawlerBlockEnabled: true,
  ddosBlockEnabled: true,
  vpnBlockEnabled: true,
  extraHoneypotPaths: [],
  extraVpnHints: [],
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: securityHeaders(new Headers({
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    })),
  });
}

function parseCookies(header) {
  const out = {};
  const src = String(header || '');
  if (!src) return out;
  for (const part of src.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) out[key] = value;
  }
  return out;
}

function b64urlEncode(value) {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlDecode(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  return atob(normalized + '='.repeat(padLen));
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret || '')),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(message || '')));
  const bytes = new Uint8Array(sig);
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return b64urlEncode(out);
}

async function signJwt(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const data = `${h}.${p}`;
  const sig = await hmacSha256Hex(secret, data);
  return `${data}.${sig}`;
}

async function verifyJwt(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const [h, p, sig] = parts;
  const data = `${h}.${p}`;
  const expected = await hmacSha256Hex(secret, data);
  if (expected !== sig) return { ok: false, reason: 'invalid_signature' };
  try {
    const payload = JSON.parse(b64urlDecode(p));
    const now = Math.floor(Date.now() / 1000);
    if (Number(payload.exp || 0) <= now) return { ok: false, reason: 'expired' };
    return { ok: true, payload };
  } catch {
    return { ok: false, reason: 'invalid_payload' };
  }
}

function getAdminPassword(env) {
  return String(env?.ADMIN_PASSWORD || 'admin999');
}

function getJwtSecret(env) {
  return String(env?.ADMIN_JWT_SECRET || env?.STATS_API_KEY || env?.ADMIN_PASSWORD || 'admin999');
}

function normalizedIps(input) {
  return [...new Set(parseIpListPayload(input).map((ip) => normalizeIp(ip)).filter(Boolean))];
}

async function readIpArray(env, key) {
  if (!env?.SHIELD_KV) return [];
  const raw = await env.SHIELD_KV.get(key, 'json');
  return normalizedIps(raw);
}

async function writeIpArray(env, key, ips) {
  if (!env?.SHIELD_KV) return;
  await env.SHIELD_KV.put(key, JSON.stringify(normalizedIps(ips)), { expirationTtl: 3650 * 24 * 3600 });
}

function normalizeStringList(value) {
  const list = Array.isArray(value) ? value : parseIpListPayload(value);
  return [...new Set(list.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean))];
}

function sanitizePolicy(raw = {}) {
  const input = raw && typeof raw === 'object' ? raw : {};
  return {
    protectEnabled: input.protectEnabled !== false,
    rateLimitEnabled: input.rateLimitEnabled !== false,
    attackBlockEnabled: input.attackBlockEnabled !== false,
    honeypotEnabled: input.honeypotEnabled !== false,
    aiCrawlerBlockEnabled: input.aiCrawlerBlockEnabled !== false,
    ddosBlockEnabled: input.ddosBlockEnabled !== false,
    vpnBlockEnabled: input.vpnBlockEnabled !== false,
    extraHoneypotPaths: normalizeStringList(input.extraHoneypotPaths || []),
    extraVpnHints: normalizeStringList(input.extraVpnHints || []),
  };
}

async function readPolicy(env) {
  if (!env?.SHIELD_KV) return { ...DEFAULT_POLICY };
  const raw = await env.SHIELD_KV.get(POLICY_KEY, 'json');
  return sanitizePolicy({ ...DEFAULT_POLICY, ...(raw || {}) });
}

async function writePolicy(env, policy) {
  if (!env?.SHIELD_KV) return;
  const safe = sanitizePolicy(policy);
  await env.SHIELD_KV.put(POLICY_KEY, JSON.stringify(safe), { expirationTtl: 3650 * 24 * 3600 });
}

async function suspendIp(env, ip, reason = 'Admin suspend', durationSeconds = 0, permanent = true) {
  if (!env?.SHIELD_KV || !ip) return null;
  const nowIso = new Date().toISOString();
  const nowSec = Math.floor(Date.now() / 1000);
  const ttl = permanent
    ? 3650 * 24 * 3600
    : Math.max(3600, Number(durationSeconds || 0));
  const until = permanent ? 0 : nowSec + ttl;

  const state = {
    ip,
    level: 999,
    strikes: 999,
    permanent: !!permanent,
    until,
    firstSeen: nowIso,
    lastSeen: nowIso,
    lastReason: String(reason || 'Admin suspend').slice(0, 140),
    lastRayId: 'admin-route',
    reasons: [{ at: nowIso, reason: String(reason || 'Admin suspend').slice(0, 120), rayId: 'admin-route' }],
  };

  await env.SHIELD_KV.put(`shield:penalty:ip:${ip}`, JSON.stringify(state), { expirationTtl: ttl });
  return state;
}

async function requireAdminAuth(request, env) {
  const auth = String(request.headers.get('authorization') || '');
  const cookies = parseCookies(request.headers.get('cookie') || '');
  const bearerToken = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const cookieToken = String(cookies.shield_admin_token || '').trim();
  const token = bearerToken || cookieToken;
  if (!token) return { ok: false, response: json({ ok: false, error: 'Unauthorized' }, 401) };
  const verified = await verifyJwt(token, getJwtSecret(env));
  if (!verified.ok) return { ok: false, response: json({ ok: false, error: 'Unauthorized', reason: verified.reason }, 401) };
  return { ok: true, payload: verified.payload };
}

async function clearIpSecurityState(env, ip) {
  if (!env?.SHIELD_KV || !ip) return { powFailKeysCleared: 0 };

  await env.SHIELD_KV.delete(`shield:rep:ip:${ip}`);
  await env.SHIELD_KV.delete(`shield:penalty:ip:${ip}`);
  await env.SHIELD_KV.delete(`shield:attacks:ip:${ip}`);

  let powFailKeysCleared = 0;
  let cursor;
  do {
    const listed = await env.SHIELD_KV.list({ prefix: `shield:pow:fail:${ip}:`, cursor, limit: 1000 });
    for (const key of (listed.keys || [])) {
      await env.SHIELD_KV.delete(key.name);
      powFailKeysCleared += 1;
    }
    cursor = listed.list_complete ? undefined : listed.cursor;
  } while (cursor);

  const blacklist = await readIpArray(env, BLACKLIST_KEY);
  const nextBlacklist = blacklist.filter((value) => value !== ip);
  if (nextBlacklist.length !== blacklist.length) {
    await writeIpArray(env, BLACKLIST_KEY, nextBlacklist);
  }

  return { powFailKeysCleared, blacklistRemoved: nextBlacklist.length !== blacklist.length };
}

async function getDashboardStats(env) {
  const now = Date.now();
  const minAgoIso = new Date(now - 60 * 1000).toISOString();
  const dayAgoIso = new Date(now - 24 * 3600 * 1000).toISOString();

  const blockedEvents = "'BLOCKED','HARD_BLOCKED','RATE_LIMITED','FAILED','ATTACK','HONEYPOT','HONEYPOT_FORM','VPN_BLOCKED','BOT_DETECTED','BOT_FARM','COUNTRY_BLOCKED'";

  const base = {
    version: 'v3',
    live: { requestsLastMinute: 0, requestsPerSecond: 0 },
    kpi: { blocked24h: 0, passed24h: 0, uniqueAttackIps24h: 0, activeCountries24h: 0 },
    topIps: [],
    countries: [],
    hourly: [],
    heatmap: [],
  };

  if (!env?.SHIELD_DB) return base;

  const [liveRow, blockedRow, passedRow, topIpsRows, countriesRows, hourlyRows, uniqueIpsRow, activeCountriesRow] = await Promise.all([
    env.SHIELD_DB.prepare('SELECT COUNT(*) AS c FROM events WHERE created_at >= ?').bind(minAgoIso).first(),
    env.SHIELD_DB.prepare(`SELECT COUNT(*) AS c FROM events WHERE created_at >= ? AND event IN (${blockedEvents})`).bind(dayAgoIso).first(),
    env.SHIELD_DB.prepare("SELECT COUNT(*) AS c FROM events WHERE created_at >= ? AND event = 'PASSED'").bind(dayAgoIso).first(),
    env.SHIELD_DB.prepare(`SELECT ip, COUNT(*) AS count FROM events WHERE created_at >= ? AND event IN (${blockedEvents}) GROUP BY ip ORDER BY count DESC LIMIT 10`).bind(dayAgoIso).all(),
    env.SHIELD_DB.prepare(`SELECT country, COUNT(*) AS count FROM events WHERE created_at >= ? AND event IN (${blockedEvents}) GROUP BY country ORDER BY count DESC LIMIT 20`).bind(dayAgoIso).all(),
    env.SHIELD_DB.prepare(`
      SELECT
        strftime('%H', created_at) AS hour,
        SUM(CASE WHEN event IN (${blockedEvents}) THEN 1 ELSE 0 END) AS blocked,
        SUM(CASE WHEN event = 'PASSED' THEN 1 ELSE 0 END) AS passed
      FROM events
      WHERE created_at >= ?
      GROUP BY strftime('%H', created_at)
      ORDER BY hour ASC
    `).bind(dayAgoIso).all(),
    env.SHIELD_DB.prepare(`SELECT COUNT(DISTINCT ip) AS c FROM events WHERE created_at >= ? AND event IN (${blockedEvents})`).bind(dayAgoIso).first(),
    env.SHIELD_DB.prepare(`SELECT COUNT(DISTINCT country) AS c FROM events WHERE created_at >= ? AND event IN (${blockedEvents})`).bind(dayAgoIso).first(),
  ]);

  const requestsLastMinute = Number(liveRow?.c || 0);
  const requestsPerSecond = Number((requestsLastMinute / 60).toFixed(2));

  const hourlyMap = new Map();
  for (let h = 0; h < 24; h += 1) {
    const key = String(h).padStart(2, '0');
    hourlyMap.set(key, { hour: key, blocked: 0, passed: 0 });
  }
  for (const row of (hourlyRows?.results || [])) {
    const key = String(row.hour || '').padStart(2, '0');
    if (!hourlyMap.has(key)) continue;
    hourlyMap.set(key, {
      hour: key,
      blocked: Number(row.blocked || 0),
      passed: Number(row.passed || 0),
    });
  }

  const hourly = [...hourlyMap.values()];

  return {
    ...base,
    live: { requestsLastMinute, requestsPerSecond },
    kpi: {
      blocked24h: Number(blockedRow?.c || 0),
      passed24h: Number(passedRow?.c || 0),
      uniqueAttackIps24h: Number(uniqueIpsRow?.c || 0),
      activeCountries24h: Number(activeCountriesRow?.c || 0),
    },
    topIps: (topIpsRows?.results || []).map((row) => ({ ip: row.ip || 'N/A', count: Number(row.count || 0) })),
    countries: (countriesRows?.results || []).map((row) => ({ country: row.country || 'N/A', count: Number(row.count || 0) })),
    hourly,
    heatmap: hourly,
  };
}

export async function resolveDashboardSession(request, env) {
  const auth = await requireAdminAuth(request, env);
  if (!auth.ok) return { ok: false, stats: null };
  const stats = await getDashboardStats(env);
  return { ok: true, stats };
}

export async function handleAdminRoutes(request, env, requesterIp = '') {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (!path.startsWith('/__shield/admin')) return null;

  if (!env?.SHIELD_KV) {
    return json({ ok: false, error: 'SHIELD_KV not configured' }, 500);
  }

  if (path === '/__shield/admin/login' && method === 'POST') {
    let payload = {};
    try {
      const contentType = String(request.headers.get('content-type') || '').toLowerCase();
      if (contentType.includes('application/json')) {
        payload = await request.json();
      } else if (contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data')) {
        const form = await request.formData();
        payload = { password: form.get('password') || '' };
      } else {
        try { payload = await request.json(); } catch {}
      }
    } catch {}
    const password = String(payload?.password || '');
    const contentType = String(request.headers.get('content-type') || '').toLowerCase();
    const formSubmit = contentType.includes('application/x-www-form-urlencoded') || contentType.includes('multipart/form-data');
    if (!password || password !== getAdminPassword(env)) {
      return json({ ok: false, error: 'Invalid credentials' }, 401);
    }
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 12 * 3600;
    const token = await signJwt({ sub: 'shield-admin', iat: now, exp }, getJwtSecret(env));
    const cookie = `shield_admin_token=${token}; Path=/; Max-Age=${12 * 3600}; HttpOnly; Secure; SameSite=Lax`;
    if (formSubmit) {
      return new Response(null, {
        status: 303,
        headers: securityHeaders(new Headers({
          location: '/shield-stats',
          'set-cookie': cookie,
          'cache-control': 'no-store',
        })),
      });
    }
    return new Response(JSON.stringify({ ok: true, token, tokenType: 'Bearer', expiresIn: 12 * 3600, expiresAt: new Date(exp * 1000).toISOString() }, null, 2), {
      status: 200,
      headers: securityHeaders(new Headers({
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'set-cookie': cookie,
      })),
    });
  }

  if (path === '/__shield/admin/logout' && (method === 'POST' || method === 'GET')) {
    return new Response(JSON.stringify({ ok: true }, null, 2), {
      status: 200,
      headers: securityHeaders(new Headers({
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'set-cookie': 'shield_admin_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax',
      })),
    });
  }

  const auth = await requireAdminAuth(request, env);
  if (!auth.ok) return auth.response;

  if (path === '/__shield/admin/blacklist' && method === 'GET') {
    const ips = await readIpArray(env, BLACKLIST_KEY);
    return json({ ok: true, count: ips.length, ips });
  }

  if (path === '/__shield/admin/blacklist/add' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const incoming = normalizedIps(payload?.ips || payload?.ip || payload);
    if (!incoming.length) return json({ ok: false, error: 'No valid IPs provided' }, 400);
    const current = await readIpArray(env, BLACKLIST_KEY);
    const merged = [...new Set([...current, ...incoming])];
    await writeIpArray(env, BLACKLIST_KEY, merged);
    return json({ ok: true, count: merged.length, ips: merged });
  }

  if (path === '/__shield/admin/blacklist/remove' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const incoming = normalizedIps(payload?.ips || payload?.ip || payload);
    const removeSet = new Set(incoming);
    const current = await readIpArray(env, BLACKLIST_KEY);
    const next = current.filter((ip) => !removeSet.has(ip));
    await writeIpArray(env, BLACKLIST_KEY, next);
    return json({ ok: true, count: next.length, ips: next });
  }

  if (path === '/__shield/admin/whitelist' && method === 'GET') {
    const ips = await readIpArray(env, WHITELIST_EXTRA_KEY);
    return json({ ok: true, count: ips.length, ips });
  }

  if (path === '/__shield/admin/whitelist/add' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const incoming = normalizedIps(payload?.ips || payload?.ip || payload);
    if (!incoming.length) return json({ ok: false, error: 'No valid IPs provided' }, 400);
    const current = await readIpArray(env, WHITELIST_EXTRA_KEY);
    const merged = [...new Set([...current, ...incoming])];
    await writeIpArray(env, WHITELIST_EXTRA_KEY, merged);
    return json({ ok: true, count: merged.length, ips: merged });
  }

  if (path === '/__shield/admin/whitelist/remove' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const incoming = normalizedIps(payload?.ips || payload?.ip || payload);
    const removeSet = new Set(incoming);
    const current = await readIpArray(env, WHITELIST_EXTRA_KEY);
    const next = current.filter((ip) => !removeSet.has(ip));
    await writeIpArray(env, WHITELIST_EXTRA_KEY, next);
    return json({ ok: true, count: next.length, ips: next });
  }

  if (path === '/__shield/admin/unblacklist' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const targetIp = normalizeIp(payload?.ip || requesterIp);
    if (!targetIp) return json({ ok: false, error: 'No valid target IP provided' }, 400);
    const result = await clearIpSecurityState(env, targetIp);
    return json({ ok: true, targetIp, ...result });
  }

  if (path === '/__shield/admin/ip/suspend' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const targetIp = normalizeIp(payload?.ip || '');
    if (!targetIp) return json({ ok: false, error: 'No valid target IP provided' }, 400);
    const permanent = payload?.permanent !== false;
    const durationSeconds = Math.max(60, Number(payload?.durationSeconds || 3600));
    const reason = String(payload?.reason || 'Admin suspend');
    const state = await suspendIp(env, targetIp, reason, durationSeconds, permanent);
    return json({ ok: true, targetIp, penalty: state });
  }

  if (path === '/__shield/admin/ip/unsuspend' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const targetIp = normalizeIp(payload?.ip || requesterIp);
    if (!targetIp) return json({ ok: false, error: 'No valid target IP provided' }, 400);
    if (env?.SHIELD_KV) {
      await env.SHIELD_KV.delete(`shield:penalty:ip:${targetIp}`);
    }
    return json({ ok: true, targetIp, unsuspended: true });
  }

  if (path === '/__shield/admin/protection' && method === 'GET') {
    const policy = await readPolicy(env);
    return json({ ok: true, policy });
  }

  if (path === '/__shield/admin/protection' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const policy = await readPolicy(env);
    const updates = payload?.updates && typeof payload.updates === 'object' ? payload.updates : payload;
    const next = sanitizePolicy({ ...policy, ...updates });
    await writePolicy(env, next);
    return json({ ok: true, policy: next });
  }

  if (path === '/__shield/admin/protection/honeypot/add' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const additions = normalizeStringList(payload?.paths || payload?.path || payload);
    const policy = await readPolicy(env);
    const merged = [...new Set([...(policy.extraHoneypotPaths || []), ...additions])];
    const next = { ...policy, extraHoneypotPaths: merged };
    await writePolicy(env, next);
    return json({ ok: true, extraHoneypotPaths: next.extraHoneypotPaths });
  }

  if (path === '/__shield/admin/protection/honeypot/remove' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const removals = new Set(normalizeStringList(payload?.paths || payload?.path || payload));
    const policy = await readPolicy(env);
    const next = {
      ...policy,
      extraHoneypotPaths: (policy.extraHoneypotPaths || []).filter((p) => !removals.has(p)),
    };
    await writePolicy(env, next);
    return json({ ok: true, extraHoneypotPaths: next.extraHoneypotPaths });
  }

  if (path === '/__shield/admin/protection/vpn-hints/add' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const additions = normalizeStringList(payload?.hints || payload?.hint || payload);
    const policy = await readPolicy(env);
    const merged = [...new Set([...(policy.extraVpnHints || []), ...additions])];
    const next = { ...policy, extraVpnHints: merged };
    await writePolicy(env, next);
    return json({ ok: true, extraVpnHints: next.extraVpnHints });
  }

  if (path === '/__shield/admin/protection/vpn-hints/remove' && method === 'POST') {
    let payload = {};
    try { payload = await request.json(); } catch {}
    const removals = new Set(normalizeStringList(payload?.hints || payload?.hint || payload));
    const policy = await readPolicy(env);
    const next = {
      ...policy,
      extraVpnHints: (policy.extraVpnHints || []).filter((p) => !removals.has(p)),
    };
    await writePolicy(env, next);
    return json({ ok: true, extraVpnHints: next.extraVpnHints });
  }

  if (path === '/__shield/admin/dashboard' && method === 'GET') {
    const stats = await getDashboardStats(env);
    return json(stats);
  }

  return json({ ok: false, error: 'Not found' }, 404);
}
