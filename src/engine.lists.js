/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Remote List Management
   ═══════════════════════════════════════════════════════════════════ */

import { LIST_CACHE_TTL, REQUIRED_LIST_KEYS } from './core.config.js';
import { normalizeStringList } from './core.utils.js';

// ─── Runtime List State ──────────────────────────────────────────
export let LISTS = {
  bot_ua_patterns: [],
  headless_hints: [],
  ai_crawler_patterns: [],
  vpn_asn_hints: [],
  honeypot_paths: [],
  sqli_patterns: [],
  xss_patterns: [],
  path_traversal_patterns: [],
  version: 'remote-required',
  source: 'uninitialized',
};

export let listsLastFetched = 0;
export let listsLoadedFromRemote = false;

// ─── Sanitization ────────────────────────────────────────────────
export function sanitizeRemoteLists(data) {
  if (!data || typeof data !== 'object') return null;
  const sanitized = {};
  for (const key of REQUIRED_LIST_KEYS) {
    if (!Array.isArray(data[key])) return null;
    sanitized[key] = normalizeStringList(data[key]);
  }
  sanitized.version = String(data.version || 'remote');
  return sanitized;
}

function adoptRemoteLists(candidate, source) {
  const safe = sanitizeRemoteLists(candidate);
  if (!safe) return false;
  LISTS = { ...LISTS, ...safe, source };
  return true;
}

// ─── Remote List Fetching ────────────────────────────────────────
export async function loadRemoteLists(env) {
  const now = Date.now();
  if (listsLoadedFromRemote && now - listsLastFetched < LIST_CACHE_TTL * 1000) return;

  let loaded = false;

  if (env?.SHIELD_KV) {
    try {
      const cached = await env.SHIELD_KV.get('remote:lists', 'json');
      if (adoptRemoteLists(cached, 'kv')) {
        listsLastFetched = now;
        listsLoadedFromRemote = true;
        loaded = true;
      }
    } catch {}
  }

  if (loaded) return;

  const listsUrl = env?.LISTS_URL;
  if (!listsUrl) {
    if (env?.SHIELD_KV) {
      try {
        const backup = await env.SHIELD_KV.get('remote:lists:last_good', 'json');
        if (adoptRemoteLists(backup, 'kv-backup')) {
          listsLastFetched = now;
          listsLoadedFromRemote = true;
        }
      } catch {}
    }
    return;
  }

  try {
    const resp = await fetch(listsUrl, {
      headers: { 'user-agent': 'Ryzeon-Shield/3.0', 'accept': 'application/json' },
      cf: { cacheTtl: 300 },
    });
    if (!resp.ok) return;
    const data = await resp.json();

    if (adoptRemoteLists(data, 'url')) {
      listsLastFetched = now;
      listsLoadedFromRemote = true;

      if (env?.SHIELD_KV) {
        try {
          await env.SHIELD_KV.put('remote:lists', JSON.stringify(LISTS), { expirationTtl: LIST_CACHE_TTL });
          await env.SHIELD_KV.put('remote:lists:last_good', JSON.stringify(LISTS), { expirationTtl: LIST_CACHE_TTL * 24 });
        } catch {}
      }
    }
  } catch {}

  if (!listsLoadedFromRemote && env?.SHIELD_KV) {
    try {
      const backup = await env.SHIELD_KV.get('remote:lists:last_good', 'json');
      if (adoptRemoteLists(backup, 'kv-backup')) {
        listsLastFetched = now;
        listsLoadedFromRemote = true;
      }
    } catch {}
  }
}

// ─── State Management (for API handlers) ─────────────────────────
export function resetListsCache() {
  listsLastFetched = 0;
  listsLoadedFromRemote = false;
}

export function setListsState(newLists) {
  LISTS = { ...LISTS, ...newLists };
  listsLastFetched = Date.now();
  listsLoadedFromRemote = true;
}
