/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Traffic Analysis, Rate Limiting & Pattern Detection
   IP rate limiting, fingerprint rate limiting, DDoS detection,
   request pattern analysis (burst, identical paths, param enumeration)
   ═══════════════════════════════════════════════════════════════════ */

import {
  SPAM_WINDOW_MS, SPAM_LIMIT, HARD_BLOCK_LIMIT,
  TRAFFIC_WINDOW_MS, DDOS_IP_THRESHOLD, DDOS_PREFIX_THRESHOLD,
  DDOS_BYTES_PER_REQUEST_EST,
} from './core.config.js';
import { getIpPrefix } from './core.utils.js';

// ─── Rate Limiting State ─────────────────────────────────────────
const ipAttempts = new Map();
const trafficBuckets = new Map();
const fpAttempts = new Map();           // fingerprint-based rate limiting
const pathTracking = new Map();          // request pattern analysis

// Fingerprint rate limits
const FP_SPAM_LIMIT = 30;               // per fingerprint per window
const FP_HARD_LIMIT = 80;

// Pattern analysis
const PATTERN_WINDOW_MS = 30 * 1000;    // 30 second window
const IDENTICAL_PATH_THRESHOLD = 10;     // same path 10+ times = suspicious
const PARAM_ENUM_THRESHOLD = 8;          // 8+ unique query params = param enumeration

// ─── IP Rate Limit Detection ─────────────────────────────────────
export function isSpam(ip, nowMs) {
  if (!ip || ip === 'N/A') return false;
  const state = ipAttempts.get(ip);
  if (!state || nowMs - state.windowStart > SPAM_WINDOW_MS) {
    ipAttempts.set(ip, { count: 1, windowStart: nowMs });
    return false;
  }
  state.count += 1;
  ipAttempts.set(ip, state);
  return state.count > SPAM_LIMIT;
}

export function isHardBlocked(ip, nowMs) {
  const state = ipAttempts.get(ip);
  if (!state) return false;
  if (nowMs - state.windowStart > SPAM_WINDOW_MS) return false;
  return state.count > HARD_BLOCK_LIMIT;
}

// ─── Fingerprint Rate Limit Detection ────────────────────────────
export function isFpSpam(fpHash, nowMs) {
  if (!fpHash) return false;
  const state = fpAttempts.get(fpHash);
  if (!state || nowMs - state.windowStart > SPAM_WINDOW_MS) {
    fpAttempts.set(fpHash, { count: 1, windowStart: nowMs });
    return false;
  }
  state.count += 1;
  fpAttempts.set(fpHash, state);
  return state.count > FP_SPAM_LIMIT;
}

export function isFpHardBlocked(fpHash, nowMs) {
  if (!fpHash) return false;
  const state = fpAttempts.get(fpHash);
  if (!state) return false;
  if (nowMs - state.windowStart > SPAM_WINDOW_MS) return false;
  return state.count > FP_HARD_LIMIT;
}

// ─── Traffic Burst / DDoS Detection ─────────────────────────────
export function detectTrafficBurst(ip, nowMs) {
  const prefix = getIpPrefix(ip);
  const ipKey = `ip:${ip}`;
  const prefixKey = `prefix:${prefix}`;

  const keys = [ipKey, prefixKey];
  const counts = {};

  for (const key of keys) {
    const state = trafficBuckets.get(key);
    if (!state || nowMs - state.windowStart > TRAFFIC_WINDOW_MS) {
      trafficBuckets.set(key, { count: 1, windowStart: nowMs });
      counts[key] = 1;
    } else {
      state.count += 1;
      counts[key] = state.count;
      trafficBuckets.set(key, state);
    }
  }

  const ipBurst = counts[ipKey] >= DDOS_IP_THRESHOLD;
  const prefixBurst = counts[prefixKey] >= DDOS_PREFIX_THRESHOLD;

  return {
    ipBurst,
    prefixBurst,
    ddosSuspect: ipBurst || prefixBurst,
    ipRate: counts[ipKey],
    prefixRate: counts[prefixKey],
    ipPrefix: prefix,
  };
}

// ─── Request Pattern Analysis ────────────────────────────────────
export function analyzeRequestPattern(ip, pathname, queryString, nowMs) {
  const key = `pattern:${ip}`;
  let state = pathTracking.get(key);

  if (!state || nowMs - state.windowStart > PATTERN_WINDOW_MS) {
    state = {
      windowStart: nowMs,
      paths: {},         // path → count
      queryParams: new Set(),
      totalRequests: 0,
    };
    pathTracking.set(key, state);
  }

  state.totalRequests += 1;
  state.paths[pathname] = (state.paths[pathname] || 0) + 1;

  // Track unique query parameter names
  if (queryString) {
    try {
      const params = new URLSearchParams(queryString);
      for (const [key] of params) {
        state.queryParams.add(key);
      }
    } catch {}
  }

  pathTracking.set(key, state);

  // Detect patterns
  const result = {
    identicalPathBurst: false,
    paramEnumeration: false,
    burstPath: null,
    uniqueParamCount: state.queryParams.size,
    patternScore: 0,
  };

  // Check for identical path bursts
  for (const [path, count] of Object.entries(state.paths)) {
    if (count >= IDENTICAL_PATH_THRESHOLD) {
      result.identicalPathBurst = true;
      result.burstPath = path;
      result.patternScore += 15;
      break;
    }
  }

  // Check for parameter enumeration (brute forcing with different params)
  if (state.queryParams.size >= PARAM_ENUM_THRESHOLD) {
    result.paramEnumeration = true;
    result.patternScore += 12;
  }

  // High request diversity (many different paths in short window)
  const uniquePaths = Object.keys(state.paths).length;
  if (uniquePaths >= 15 && state.totalRequests >= 20) {
    result.patternScore += 10; // scanning/discovery behavior
  }

  return result;
}

// ─── Prevented Traffic Estimation ────────────────────────────────
export function estimatePreventedBytes(request, signals) {
  const hinted = Number(request.headers.get('content-length') || 0);
  const base = hinted > 0 ? Math.min(hinted, 2 * 1024 * 1024) : DDOS_BYTES_PER_REQUEST_EST;
  let multiplier = 1;
  if (signals?.ddosSuspect) multiplier += 1.5;
  if (signals?._attackFlags?.length || signals?.attackFlags?.length) multiplier += 0.7;
  return Math.round(base * multiplier);
}

export async function addPreventedTraffic(env, bytes) {
  if (!env?.SHIELD_KV) return 0;
  const day = new Date().toISOString().slice(0, 10);
  const key = `shield:ddos:prevented:${day}`;
  const current = Number((await env.SHIELD_KV.get(key)) || '0');
  const updated = current + Math.max(0, Number(bytes || 0));
  await env.SHIELD_KV.put(key, String(updated), { expirationTtl: 90 * 24 * 3600 });
  return updated;
}

// ─── Header Presence Score ───────────────────────────────────────
export function getHeaderPresenceScore(request) {
  const browserLikeHeaders = [
    'accept', 'accept-language', 'accept-encoding',
    'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-dest',
    'sec-ch-ua', 'sec-ch-ua-platform',
  ];
  let score = 0;
  for (const headerName of browserLikeHeaders) {
    if (request.headers.get(headerName)) score += 1;
  }
  return score;
}
