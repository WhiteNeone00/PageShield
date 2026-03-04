/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — API Route Handlers
   Stats, list management, blacklist management
   ═══════════════════════════════════════════════════════════════════ */

import { LIST_CACHE_TTL } from './core.config.js';
import { securityHeaders, normalizeIp, penaltyLabel, parseIpListPayload } from './core.utils.js';
import { kvGetJson } from './core.storage.js';
import {
  LISTS, listsLoadedFromRemote, listsLastFetched,
  loadRemoteLists, resetListsCache, setListsState, sanitizeRemoteLists,
} from './engine.lists.js';
import {
  dynamicIpBlacklist, blacklistLoadedFromRemote, blacklistLastFetched,
  loadDynamicIpBlacklist, resetBlacklistCache, getMergedStaticBlacklist,
  setDynamicBlacklist,
} from './engine.blacklist.js';

const WHITELIST_EXTRA_KEY = 'shield:whitelist:extra';

function normalizeIpSet(values) {
  return [...new Set((values || []).map((value) => normalizeIp(value)).filter(Boolean))];
}

async function readWhitelistExtraIps(env) {
  if (!env?.SHIELD_KV) return [];
  const raw = await env.SHIELD_KV.get(WHITELIST_EXTRA_KEY, 'json');
  return normalizeIpSet(parseIpListPayload(raw));
}

async function writeWhitelistExtraIps(env, ips) {
  if (!env?.SHIELD_KV) return;
  const normalized = normalizeIpSet(ips);
  await env.SHIELD_KV.put(WHITELIST_EXTRA_KEY, JSON.stringify(normalized), { expirationTtl: 3650 * 24 * 3600 });
}

// ─── Stats API ───────────────────────────────────────────────────
export async function handleStatsApi(env) {
  const day = new Date().toISOString().slice(0, 10);
  const result = {
    date: day,
    version: '3.0',
    listsLoaded: listsLoadedFromRemote,
    listsSource: LISTS.source || 'uninitialized',
    listsVersion: LISTS.version || 'unknown',
  };
  result.blacklist = {
    count: dynamicIpBlacklist.size,
    loadedFromRemote: blacklistLoadedFromRemote,
    lastFetched: blacklistLastFetched ? new Date(blacklistLastFetched).toISOString() : null,
  };

  if (env?.SHIELD_KV) {
    const keys = ['passed', 'blocked', 'failed', 'expired', 'honeypot', 'challenged', 'attack', 'total'];
    const kv = {};
    for (const k of keys) {
      kv[k] = parseInt((await env.SHIELD_KV.get('stats:' + day + ':' + k)) || '0', 10);
    }
    result.kv = kv;
  }

  if (env?.SHIELD_DB) {
    try {
      const recentRows = await env.SHIELD_DB.prepare(
        'SELECT id, event, reason, ip, country, host, path, threat_score, created_at FROM events ORDER BY id DESC LIMIT 25'
      ).all();
      result.recent = recentRows.results || [];

      const topBlocked = await env.SHIELD_DB.prepare(
        "SELECT ip, country, COUNT(*) AS cnt FROM events WHERE event IN ('BLOCKED','HARD_BLOCKED','HONEYPOT','ATTACK') AND created_at >= ? GROUP BY ip ORDER BY cnt DESC LIMIT 10"
      ).bind(day + 'T00:00:00Z').all();
      result.topBlocked = topBlocked.results || [];

      const countRow = await env.SHIELD_DB.prepare('SELECT COUNT(*) AS total FROM events').first();
      result.totalEventsD1 = countRow?.total || 0;
    } catch (e) {
      result.d1Error = e.message;
    }
  }

  if (env?.SHIELD_R2) {
    try {
      const listed = await env.SHIELD_R2.list({ prefix: day + '/', limit: 5 });
      result.r2TodaySnapshots = listed.objects?.length || 0;
      result.r2Truncated = listed.truncated;
    } catch (e) {
      result.r2Error = e.message;
    }
  }

  // DDOS prevented traffic
  if (env?.SHIELD_KV) {
    try {
      const prevented = await kvGetJson(env, 'shield:ddos:prevented:' + day);
      result.ddosPrevented = prevented || { requests: 0, bytes: 0 };
    } catch (e) { result.ddosPreventedError = e.message; }
  }

  // Active penalties
  if (env?.SHIELD_KV) {
    try {
      const penaltyList = await env.SHIELD_KV.list({ prefix: 'shield:penalty:ip:', limit: 100 });
      const activePenalties = [];
      for (const key of (penaltyList.keys || [])) {
        const p = await kvGetJson(env, key.name);
        if (p) {
          const label = penaltyLabel(p.level, p.permanent);
          const remaining = p.permanent ? 'permanent' : Math.max(0, Math.round(((p.until || 0) * 1000 - Date.now()) / 1000)) + 's';
          activePenalties.push({ ip: key.name.replace('shield:penalty:ip:', ''), level: p.level, label, remaining, strikes: p.strikes || 0 });
        }
      }
      result.penalties = { total: activePenalties.length, active: activePenalties };
    } catch (e) { result.penaltiesError = e.message; }
  }

  // Deployed version
  if (env?.SHIELD_KV) {
    try {
      const deployed = await env.SHIELD_KV.get('shield:meta:deployed_version');
      result.deployedVersion = deployed || null;
    } catch {}
  }

  return new Response(JSON.stringify(result, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── List Reload API ─────────────────────────────────────────────
export async function handleListReload(env) {
  resetListsCache();
  await loadRemoteLists(env);
  return new Response(JSON.stringify({
    ok: true,
    loadedFromRemote: listsLoadedFromRemote,
    source: LISTS.source,
    listsVersion: LISTS.version || 'unknown',
    counts: {
      bot_ua_patterns: LISTS.bot_ua_patterns.length,
      headless_hints: LISTS.headless_hints.length,
      ai_crawler_patterns: LISTS.ai_crawler_patterns.length,
      vpn_asn_hints: LISTS.vpn_asn_hints.length,
      honeypot_paths: LISTS.honeypot_paths.length,
      sqli_patterns: LISTS.sqli_patterns.length,
      xss_patterns: LISTS.xss_patterns.length,
      path_traversal_patterns: LISTS.path_traversal_patterns.length,
    },
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── Blacklist Reload API ────────────────────────────────────────
export async function handleBlacklistReload(env) {
  resetBlacklistCache();
  await loadDynamicIpBlacklist(env);
  return new Response(JSON.stringify({
    ok: true,
    source: env?.BLACKLIST_URL ? 'kv+url+d1+env' : 'kv+d1+env',
    count: dynamicIpBlacklist.size,
    sample: Array.from(dynamicIpBlacklist).slice(0, 20),
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── Blacklist View API ──────────────────────────────────────────
export async function handleBlacklistView() {
  return new Response(JSON.stringify({
    count: dynamicIpBlacklist.size,
    ips: Array.from(dynamicIpBlacklist),
    lastFetched: blacklistLastFetched ? new Date(blacklistLastFetched).toISOString() : null,
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── Blacklist Update API ────────────────────────────────────────
export async function handleBlacklistUpdate(env, request) {
  const payload = await request.json();
  const ips = parseIpListPayload(payload).map((ip) => normalizeIp(ip)).filter(Boolean);

  if (!ips.length) {
    return new Response(JSON.stringify({ ok: false, error: 'No valid IPs provided' }), {
      status: 400,
      headers: securityHeaders(new Headers({ 'content-type': 'application/json' })),
    });
  }

  if (env?.SHIELD_KV) {
    await env.SHIELD_KV.put('remote:blacklisted_ips', JSON.stringify(ips), { expirationTtl: LIST_CACHE_TTL * 24 });
  }

  const merged = getMergedStaticBlacklist(env);
  ips.forEach((ip) => merged.add(ip));
  setDynamicBlacklist(merged);

  return new Response(JSON.stringify({
    ok: true,
    count: dynamicIpBlacklist.size,
    message: 'Blacklist updated',
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── Unblacklist / Clear Penalty API ────────────────────────────
export async function handleUnblacklist(env, request, requesterIp = '') {
  let payload = {};
  try {
    payload = await request.json();
  } catch {}

  const targetIp = normalizeIp(payload?.ip || requesterIp);
  if (!targetIp) {
    return new Response(JSON.stringify({ ok: false, error: 'No valid target IP provided' }), {
      status: 400,
      headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
    });
  }

  const result = {
    targetIp,
    penaltyCleared: false,
    attackMemoryCleared: false,
    powFailKeysCleared: 0,
    remoteBlacklistRemoved: false,
  };

  if (env?.SHIELD_KV) {
    const penaltyKey = `shield:penalty:ip:${targetIp}`;
    const attackKey = `shield:attacks:ip:${targetIp}`;

    try {
      const existed = await env.SHIELD_KV.get(penaltyKey);
      await env.SHIELD_KV.delete(penaltyKey);
      result.penaltyCleared = existed !== null;
    } catch {}

    try {
      const existed = await env.SHIELD_KV.get(attackKey);
      await env.SHIELD_KV.delete(attackKey);
      result.attackMemoryCleared = existed !== null;
    } catch {}

    try {
      let cursor;
      do {
        const listed = await env.SHIELD_KV.list({ prefix: `shield:pow:fail:${targetIp}:`, cursor, limit: 1000 });
        for (const key of (listed.keys || [])) {
          await env.SHIELD_KV.delete(key.name);
          result.powFailKeysCleared += 1;
        }
        cursor = listed.list_complete ? undefined : listed.cursor;
      } while (cursor);
    } catch {}

    try {
      const remoteRaw = await env.SHIELD_KV.get('remote:blacklisted_ips', 'json');
      const remoteIps = parseIpListPayload(remoteRaw).map((value) => normalizeIp(value)).filter(Boolean);
      const filtered = remoteIps.filter((value) => value !== targetIp);
      if (filtered.length !== remoteIps.length) {
        await env.SHIELD_KV.put('remote:blacklisted_ips', JSON.stringify(filtered), { expirationTtl: LIST_CACHE_TTL * 24 });
        result.remoteBlacklistRemoved = true;
      }
    } catch {}
  }

  return new Response(JSON.stringify({ ok: true, ...result }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── Runtime Extra Whitelist API ───────────────────────────────
export async function handleWhitelistExtraView(env) {
  const ips = await readWhitelistExtraIps(env);
  return new Response(JSON.stringify({ ok: true, count: ips.length, ips }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

export async function handleWhitelistExtraUpdate(env, request) {
  let payload = {};
  try {
    payload = await request.json();
  } catch {}

  const action = String(payload?.action || 'set').toLowerCase();
  const incomingIps = normalizeIpSet(parseIpListPayload(payload?.ips || payload?.ip || payload));
  const currentIps = await readWhitelistExtraIps(env);
  let nextIps = currentIps;

  if (action === 'set') {
    nextIps = incomingIps;
  } else if (action === 'add') {
    nextIps = normalizeIpSet([...currentIps, ...incomingIps]);
  } else if (action === 'remove') {
    const removeSet = new Set(incomingIps);
    nextIps = currentIps.filter((ip) => !removeSet.has(ip));
  } else if (action === 'clear') {
    nextIps = [];
  } else {
    return new Response(JSON.stringify({ ok: false, error: 'Invalid action. Use set, add, remove, or clear.' }), {
      status: 400,
      headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
    });
  }

  await writeWhitelistExtraIps(env, nextIps);

  return new Response(JSON.stringify({
    ok: true,
    action,
    count: nextIps.length,
    ips: nextIps,
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── List Update API ─────────────────────────────────────────────
export async function handleListUpdate(env, request) {
  const newLists = await request.json();
  const safeLists = sanitizeRemoteLists(newLists);
  if (!safeLists) {
    return new Response(JSON.stringify({ ok: false, error: 'Invalid lists format - required keys missing or malformed arrays' }), {
      status: 400, headers: securityHeaders(new Headers({ 'content-type': 'application/json' })),
    });
  }
  const storedLists = {
    ...safeLists,
    version: String(newLists.version || 'api-manual'),
    source: 'api',
  };
  if (env?.SHIELD_KV) {
    await env.SHIELD_KV.put('remote:lists', JSON.stringify(storedLists), { expirationTtl: LIST_CACHE_TTL * 24 });
    await env.SHIELD_KV.put('remote:lists:last_good', JSON.stringify(storedLists), { expirationTtl: LIST_CACHE_TTL * 24 * 7 });
  }
  setListsState(storedLists);
  return new Response(JSON.stringify({
    ok: true,
    message: 'Lists updated successfully',
    counts: {
      bot_ua_patterns: LISTS.bot_ua_patterns.length,
      headless_hints: LISTS.headless_hints.length,
      ai_crawler_patterns: LISTS.ai_crawler_patterns.length,
      vpn_asn_hints: LISTS.vpn_asn_hints.length,
      honeypot_paths: LISTS.honeypot_paths.length,
      sqli_patterns: (LISTS.sqli_patterns || []).length,
      xss_patterns: (LISTS.xss_patterns || []).length,
      path_traversal_patterns: (LISTS.path_traversal_patterns || []).length,
    },
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}

// ─── List View API ───────────────────────────────────────────────
export async function handleListView() {
  return new Response(JSON.stringify({
    source: LISTS.source || 'uninitialized',
    loadedFromRemote: listsLoadedFromRemote,
    version: LISTS.version || 'unknown',
    lastFetched: listsLastFetched ? new Date(listsLastFetched).toISOString() : null,
    counts: {
      bot_ua_patterns: LISTS.bot_ua_patterns.length,
      headless_hints: LISTS.headless_hints.length,
      ai_crawler_patterns: LISTS.ai_crawler_patterns.length,
      vpn_asn_hints: LISTS.vpn_asn_hints.length,
      honeypot_paths: LISTS.honeypot_paths.length,
      sqli_patterns: (LISTS.sqli_patterns || []).length,
      xss_patterns: (LISTS.xss_patterns || []).length,
      path_traversal_patterns: (LISTS.path_traversal_patterns || []).length,
    },
    lists: LISTS,
  }, null, 2), {
    headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
  });
}
