/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Protected Sites Registry (Multi-tenant SaaS)
   D1-backed domain lookup with in-memory cache
   ═══════════════════════════════════════════════════════════════════ */

// ─── In-Memory Site Cache ────────────────────────────────────────
const siteCache = new Map();
const CACHE_TTL_MS = 60 * 1000; // 1 minute
const CACHE_MAX = 500;

function cacheCleanup() {
  if (siteCache.size <= CACHE_MAX) return;
  const now = Date.now();
  for (const [k, v] of siteCache) {
    if (v._cacheExp <= now) siteCache.delete(k);
  }
  if (siteCache.size > CACHE_MAX) {
    const entries = [...siteCache.entries()].sort((a, b) => a[1]._cacheExp - b[1]._cacheExp);
    for (let i = 0, n = Math.floor(entries.length / 2); i < n; i++) siteCache.delete(entries[i][0]);
  }
}

/**
 * Look up a protected site by domain.
 * Returns { found: true, site: {...} } or { found: false }
 * Caches results in memory for 1 minute.
 */
export async function lookupSite(env, domain) {
  const key = String(domain || '').toLowerCase().trim();
  if (!key) return { found: false };

  // Check memory cache
  const cached = siteCache.get(key);
  if (cached && cached._cacheExp > Date.now()) {
    return cached.site ? { found: true, site: cached.site } : { found: false };
  }

  if (!env?.SHIELD_DB) return { found: false };

  try {
    const row = await env.SHIELD_DB.prepare(
      'SELECT id, domain, origin_url, owner_email, plan, api_key, settings, active FROM protected_sites WHERE domain = ? LIMIT 1'
    ).bind(key).first();

    if (!row || !row.active) {
      siteCache.set(key, { site: null, _cacheExp: Date.now() + CACHE_TTL_MS });
      cacheCleanup();
      return { found: false };
    }

    let settings = {};
    try { settings = JSON.parse(row.settings || '{}'); } catch { settings = {}; }

    const site = {
      id: row.id,
      domain: row.domain,
      originUrl: String(row.origin_url || '').trim(),
      ownerEmail: row.owner_email || '',
      plan: row.plan || 'free',
      apiKey: row.api_key || '',
      settings,
      active: !!row.active,
    };

    siteCache.set(key, { site, _cacheExp: Date.now() + CACHE_TTL_MS });
    cacheCleanup();
    return { found: true, site };
  } catch {
    return { found: false };
  }
}

/**
 * List all protected sites.
 */
export async function listSites(env) {
  if (!env?.SHIELD_DB) return [];
  try {
    const result = await env.SHIELD_DB.prepare(
      'SELECT id, domain, origin_url, owner_email, plan, api_key, active, created_at, updated_at FROM protected_sites ORDER BY created_at DESC'
    ).all();
    return (result?.results || []).map(row => ({
      id: row.id,
      domain: row.domain,
      originUrl: row.origin_url,
      ownerEmail: row.owner_email || '',
      plan: row.plan || 'free',
      apiKey: row.api_key || '',
      active: !!row.active,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }));
  } catch {
    return [];
  }
}

/**
 * Add a protected site.
 */
export async function addSite(env, domain, originUrl, ownerEmail = '', plan = 'free') {
  if (!env?.SHIELD_DB) return { ok: false, error: 'No database' };
  const d = String(domain || '').toLowerCase().trim();
  const o = String(originUrl || '').trim();
  if (!d) return { ok: false, error: 'Domain is required' };
  if (!o) return { ok: false, error: 'Origin URL is required' };

  // Validate origin URL format
  try {
    const parsed = new URL(o.startsWith('http') ? o : 'https://' + o);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { ok: false, error: 'Origin must be http or https' };
    }
  } catch {
    return { ok: false, error: 'Invalid origin URL' };
  }

  const normalizedOrigin = o.startsWith('http') ? o : 'https://' + o;
  const apiKey = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');

  try {
    await env.SHIELD_DB.prepare(
      'INSERT INTO protected_sites (domain, origin_url, owner_email, plan, api_key, settings) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(d, normalizedOrigin, ownerEmail, plan, apiKey, '{}').run();

    // Invalidate cache
    siteCache.delete(d);

    return { ok: true, domain: d, originUrl: normalizedOrigin, apiKey };
  } catch (err) {
    if (String(err?.message || '').includes('UNIQUE')) {
      return { ok: false, error: 'Domain already registered' };
    }
    return { ok: false, error: String(err?.message || 'Database error') };
  }
}

/**
 * Remove a protected site.
 */
export async function removeSite(env, domain) {
  if (!env?.SHIELD_DB) return { ok: false, error: 'No database' };
  const d = String(domain || '').toLowerCase().trim();
  if (!d) return { ok: false, error: 'Domain is required' };

  try {
    const result = await env.SHIELD_DB.prepare('DELETE FROM protected_sites WHERE domain = ?').bind(d).run();
    siteCache.delete(d);
    return { ok: true, deleted: (result?.meta?.changes || 0) > 0 };
  } catch (err) {
    return { ok: false, error: String(err?.message || 'Database error') };
  }
}

/**
 * Update a protected site.
 */
export async function updateSite(env, domain, updates = {}) {
  if (!env?.SHIELD_DB) return { ok: false, error: 'No database' };
  const d = String(domain || '').toLowerCase().trim();
  if (!d) return { ok: false, error: 'Domain is required' };

  const sets = [];
  const binds = [];

  if (updates.originUrl !== undefined) {
    const o = String(updates.originUrl || '').trim();
    const normalizedOrigin = o.startsWith('http') ? o : 'https://' + o;
    sets.push('origin_url = ?');
    binds.push(normalizedOrigin);
  }
  if (updates.ownerEmail !== undefined) {
    sets.push('owner_email = ?');
    binds.push(String(updates.ownerEmail || ''));
  }
  if (updates.plan !== undefined) {
    sets.push('plan = ?');
    binds.push(String(updates.plan || 'free'));
  }
  if (updates.active !== undefined) {
    sets.push('active = ?');
    binds.push(updates.active ? 1 : 0);
  }
  if (updates.settings !== undefined) {
    sets.push('settings = ?');
    binds.push(JSON.stringify(updates.settings || {}));
  }

  if (sets.length === 0) return { ok: false, error: 'No updates provided' };

  sets.push("updated_at = datetime('now')");
  binds.push(d);

  try {
    await env.SHIELD_DB.prepare(
      `UPDATE protected_sites SET ${sets.join(', ')} WHERE domain = ?`
    ).bind(...binds).run();

    siteCache.delete(d);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err?.message || 'Database error') };
  }
}

/**
 * Create a proxied request to the origin server.
 * Preserves the original Host header so the origin knows which site is being requested.
 */
export function buildOriginRequest(originalRequest, site) {
  const url = new URL(originalRequest.url);
  const originBase = String(site.originUrl || '').replace(/\/+$/, '');
  const originFull = originBase + url.pathname + url.search;

  const headers = new Headers(originalRequest.headers);
  // Set Host to the customer's domain so origin virtual hosts work
  headers.set('Host', site.domain);
  // Pass real client IP
  headers.set('X-Forwarded-For', originalRequest.headers.get('cf-connecting-ip') || '');
  headers.set('X-Forwarded-Proto', 'https');
  headers.set('X-Forwarded-Host', site.domain);
  headers.set('X-Shield-Protected', 'true');

  return new Request(originFull, {
    method: originalRequest.method,
    headers,
    body: originalRequest.body,
    redirect: 'manual',
  });
}
