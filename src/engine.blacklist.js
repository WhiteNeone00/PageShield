/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Dynamic IP Blacklist Management
   ═══════════════════════════════════════════════════════════════════ */

import { BLACKLIST_CACHE_TTL } from './core.config.js';
import { normalizeIp, parseIpListPayload } from './core.utils.js';

// ─── Blacklist State ─────────────────────────────────────────────
export let dynamicIpBlacklist = new Set();
export let blacklistLastFetched = 0;
export let blacklistLoadedFromRemote = false;

// ─── Static Blacklist from Env ───────────────────────────────────
export function getMergedStaticBlacklist(env) {
  const inline = (env?.IP_BLACKLIST || '').split(',').map((s) => normalizeIp(s)).filter(Boolean);
  return new Set(inline);
}

// ─── Load Dynamic Blacklist (KV + URL + D1 + Env) ───────────────
export async function loadDynamicIpBlacklist(env) {
  const now = Date.now();
  if (blacklistLoadedFromRemote && now - blacklistLastFetched < BLACKLIST_CACHE_TTL * 1000) return;

  const merged = getMergedStaticBlacklist(env);

  if (env?.SHIELD_KV) {
    try {
      const cached = await env.SHIELD_KV.get('remote:blacklisted_ips', 'json');
      const cachedIps = parseIpListPayload(cached);
      for (const ip of cachedIps) {
        const n = normalizeIp(ip);
        if (n) merged.add(n);
      }
    } catch {}
  }

  const blacklistUrl = env?.BLACKLIST_URL;
  if (blacklistUrl) {
    try {
      const resp = await fetch(blacklistUrl, {
        headers: { 'user-agent': 'Ryzeon-Shield/3.0', 'accept': 'application/json,text/plain' },
        cf: { cacheTtl: 300 },
      });
      if (resp.ok) {
        const contentType = (resp.headers.get('content-type') || '').toLowerCase();
        let payload;
        if (contentType.includes('application/json')) {
          payload = await resp.json();
        } else {
          payload = await resp.text();
        }
        const urlIps = parseIpListPayload(payload);
        for (const ip of urlIps) {
          const n = normalizeIp(ip);
          if (n) merged.add(n);
        }
        if (env?.SHIELD_KV && urlIps.length) {
          try {
            await env.SHIELD_KV.put('remote:blacklisted_ips', JSON.stringify(urlIps), { expirationTtl: BLACKLIST_CACHE_TTL });
          } catch {}
        }
      }
    } catch {}
  }

  if (env?.SHIELD_DB) {
    try {
      const rows = await env.SHIELD_DB.prepare('SELECT ip FROM ip_blacklist WHERE enabled = 1 ORDER BY ip ASC LIMIT 5000').all();
      const d1Rows = rows?.results || [];
      for (const row of d1Rows) {
        const n = normalizeIp(row?.ip);
        if (n) merged.add(n);
      }
    } catch {}
  }

  dynamicIpBlacklist = merged;
  blacklistLastFetched = now;
  blacklistLoadedFromRemote = true;
}

// ─── State Management (for API handlers) ─────────────────────────
export function resetBlacklistCache() {
  blacklistLastFetched = 0;
  blacklistLoadedFromRemote = false;
}

export function setDynamicBlacklist(newSet) {
  dynamicIpBlacklist = newSet;
  blacklistLastFetched = Date.now();
  blacklistLoadedFromRemote = true;
}
