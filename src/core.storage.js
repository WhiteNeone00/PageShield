/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — KV Storage Helpers
   ═══════════════════════════════════════════════════════════════════ */

const KV_DISABLED_VALUES = new Set(['1', 'true', 'yes', 'on']);

function isKvDisabled(env) {
  const raw = String(env?.DISABLE_KV || env?.SHIELD_KV_DISABLED || '').trim().toLowerCase();
  return KV_DISABLED_VALUES.has(raw);
}

function canUseKv(env) {
  return !!env?.SHIELD_KV && !isKvDisabled(env);
}

export async function kvGetJson(env, key) {
  if (!canUseKv(env)) return null;
  try {
    return await env.SHIELD_KV.get(key, 'json');
  } catch {
    return null;
  }
}

export async function kvPutJson(env, key, value, ttl) {
  if (!canUseKv(env)) return;
  try {
    if (ttl) await env.SHIELD_KV.put(key, JSON.stringify(value), { expirationTtl: ttl });
    else await env.SHIELD_KV.put(key, JSON.stringify(value));
  } catch {}
}
