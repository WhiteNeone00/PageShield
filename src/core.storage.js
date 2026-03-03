/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — KV Storage Helpers
   ═══════════════════════════════════════════════════════════════════ */

export async function kvGetJson(env, key) {
  if (!env?.SHIELD_KV) return null;
  try {
    return await env.SHIELD_KV.get(key, 'json');
  } catch {
    return null;
  }
}

export async function kvPutJson(env, key, value, ttl) {
  if (!env?.SHIELD_KV) return;
  try {
    if (ttl) await env.SHIELD_KV.put(key, JSON.stringify(value), { expirationTtl: ttl });
    else await env.SHIELD_KV.put(key, JSON.stringify(value));
  } catch {}
}
