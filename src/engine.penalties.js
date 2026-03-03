/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Penalty System
   ═══════════════════════════════════════════════════════════════════ */

import { PENALTY_STEPS } from './core.config.js';
import { clip, normalizeIp } from './core.utils.js';
import { kvGetJson, kvPutJson } from './core.storage.js';
import { dynamicIpBlacklist } from './engine.blacklist.js';

// ─── Penalty Computation ─────────────────────────────────────────
function nextPenalty(state) {
  const currentLevel = Math.max(0, Number(state?.level || 0));
  const nextLevel = Math.min(currentLevel + 1, PENALTY_STEPS.length - 1);
  const duration = PENALTY_STEPS[nextLevel];
  if (duration < 0) {
    return { level: nextLevel, until: 0, permanent: true };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  return { level: nextLevel, until: nowSec + duration, permanent: false };
}

// ─── Get Penalty State ───────────────────────────────────────────
export async function getPenaltyState(env, ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return null;
  return await kvGetJson(env, `shield:penalty:ip:${normalized}`);
}

// ─── Escalate Penalty ────────────────────────────────────────────
export async function escalateIpPenalty(env, ip, reason, details = {}) {
  if (!env?.SHIELD_KV) return null;
  const normalized = normalizeIp(ip);
  if (!normalized) return null;

  const prev = (await getPenaltyState(env, normalized)) || {
    ip: normalized,
    level: -1,
    strikes: 0,
    permanent: false,
    until: 0,
    firstSeen: new Date().toISOString(),
    lastSeen: null,
    reasons: [],
  };

  const nowIso = new Date().toISOString();
  const next = nextPenalty(prev);
  const reasons = Array.isArray(prev.reasons) ? prev.reasons.slice(-20) : [];
  reasons.push({ at: nowIso, reason: clip(reason, 120), rayId: details.rayId || 'N/A' });

  const state = {
    ...prev,
    ip: normalized,
    level: next.level,
    strikes: Number(prev.strikes || 0) + 1,
    permanent: next.permanent,
    until: next.until,
    lastSeen: nowIso,
    reasons,
    lastReason: clip(reason, 140),
    lastRayId: details.rayId || 'N/A',
  };

  const ttl = next.permanent ? 3650 * 24 * 3600 : Math.max(86400, next.until - Math.floor(Date.now() / 1000) + 86400);
  await kvPutJson(env, `shield:penalty:ip:${normalized}`, state, ttl);
  return state;
}

// ─── Set Permanent Penalty ───────────────────────────────────────
export async function setPermanentPenalty(env, ip, reason, details = {}) {
  if (!env?.SHIELD_KV) return null;
  const normalized = normalizeIp(ip);
  if (!normalized) return null;
  const nowIso = new Date().toISOString();
  const state = {
    ip: normalized,
    level: PENALTY_STEPS.length - 1,
    strikes: 999,
    permanent: true,
    until: 0,
    firstSeen: nowIso,
    lastSeen: nowIso,
    lastReason: clip(reason, 140),
    lastRayId: details.rayId || 'N/A',
    reasons: [{ at: nowIso, reason: clip(reason, 120), rayId: details.rayId || 'N/A' }],
  };
  await kvPutJson(env, `shield:penalty:ip:${normalized}`, state, 3650 * 24 * 3600);
  return state;
}

// ─── Check IP Blacklist Status (static + dynamic + penalty) ──────
export async function getIpBlacklistStatus(env, ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return { blocked: false, source: 'none', penalty: null };
  if (dynamicIpBlacklist.has(normalized)) return { blocked: true, source: 'dynamic', penalty: null };

  const inline = (env?.IP_BLACKLIST || '').split(',').map((s) => normalizeIp(s)).filter(Boolean);
  if (inline.includes(normalized)) return { blocked: true, source: 'inline', penalty: null };

  const state = await getPenaltyState(env, normalized);
  if (!state) return { blocked: false, source: 'none', penalty: null };
  const nowSec = Math.floor(Date.now() / 1000);
  const active = !!state.permanent || (Number(state.until || 0) > nowSec);
  if (!active) return { blocked: false, source: 'none', penalty: state };
  return { blocked: true, source: state.permanent ? 'penalty-permanent' : 'penalty-timed', penalty: state };
}
