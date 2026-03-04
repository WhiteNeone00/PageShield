/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Main Worker Entry Point
   Cloudflare Worker fetch handler — with challenge escalation,
   specific block pages, behavioral analysis, IP reputation,
   fingerprint reuse detection, and weighted AI scoring
   ═══════════════════════════════════════════════════════════════════ */

import {
  COOKIE_NAME, COOKIE_EXP_NAME, COOKIE_SIG_NAME,
  COOKIE_FP_NAME, COOKIE_RISK_NAME, COOKIE_MAX_AGE,
  POW_DIFFICULTY, CHALLENGE_NONCE_TTL, DEFAULT_POLICY,
  POLICY_KEY,
} from './core.config.js';
import { getClientIp, parseCookies, securityHeaders, clip, penaltyLabel, sha256 } from './core.utils.js';
import { kvGetJson, kvPutJson } from './core.storage.js';
import { LISTS, loadRemoteLists } from './engine.lists.js';
import { loadDynamicIpBlacklist } from './engine.blacklist.js';
import { escalateIpPenalty, setPermanentPenalty, getIpBlacklistStatus } from './engine.penalties.js';
import {
  storeBehaviorProfile, loadBehaviorRisk, loadIpReputation,
  updateThreatIntel, scoreBehavior, scoreHoneypot,
} from './engine.behavior.js';
import { estimatePreventedBytes, addPreventedTraffic } from './engine.traffic.js';
import {
  buildDetectionSignals, computeThreatScore, determineEscalation,
  isCountryBlocked, isIpWhitelisted, shouldProtect,
} from './engine.detection.js';
import { hmacSign, hmacVerify, getSigningSecret, deriveRequestFingerprint } from './core.crypto.js';
import {
  sendDiscordWebhook, sendExternalLog, logToD1, logErrorToD1,
  saveToR2, incrementKvStat, emitDeploymentEventIfNeeded,
} from './middleware.webhooks.js';
import {
  htmlChallenge, htmlHardBlock,
  htmlRateLimited, htmlVpnBlocked, htmlSuspended, htmlCountryBlocked,
  htmlDdosBlocked, htmlAiCrawlerBlocked, htmlBotDetected,
  htmlAttackBlocked, htmlHoneypotTriggered, htmlServiceDown,
} from './views.challenge.js';
import { htmlShieldStats } from './views.dashboard.js';
import {
  handleStatsApi, handleListReload, handleBlacklistReload,
  handleBlacklistView, handleBlacklistUpdate, handleListUpdate, handleListView,
  handleUnblacklist, handleWhitelistExtraView, handleWhitelistExtraUpdate,
} from './middleware.api.js';
import { handleAdminRoutes, resolveDashboardSession } from './admin.routes.js';
import { lookupSite, buildOriginRequest } from './engine.sites.js';

const FP_HASH_RE = /^[a-f0-9]{64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SIG_RE = /^[a-f0-9]{64}$/i;
const CHALLENGE_MIN_TTL = 30;
const CHALLENGE_MAX_TTL = 120;
const COOKIE_RECHECK_NAME = 'cf_shield_recheck';
const VERIFIED_RECHECK_COOLDOWN = 300;

const SENSITIVE_AUTH_PATHS = new Set([
  '/login', '/signin', '/auth', '/auth/login', '/api/token', '/oauth/token',
  '/wp-login.php', '/xmlrpc.php', '/admin/login', '/user/login',
]);

// ─── Origin Health Cache (suppress repeated ERROR webhooks) ─────
const originDownCache = new Map();
const ORIGIN_DOWN_SUPPRESS_MS = 10 * 60 * 1000; // 10 min

function isOriginKnownDown(host) {
  const exp = originDownCache.get(host);
  if (!exp) return false;
  if (Date.now() > exp) { originDownCache.delete(host); return false; }
  return true;
}

function markOriginDown(host) {
  originDownCache.set(host, Date.now() + ORIGIN_DOWN_SUPPRESS_MS);
  // Cap cache size
  if (originDownCache.size > 200) {
    const now = Date.now();
    for (const [k, v] of originDownCache) { if (v <= now) originDownCache.delete(k); }
  }
}

function clamp(num, min, max) {
  return Math.max(min, Math.min(max, num));
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendDiscordWebhookDelayed(env, eventType, reason, details, ms = 3000) {
  await delay(ms);
  return sendDiscordWebhook(env, eventType, reason, details);
}

function normalizeClientSnapshot(input) {
  if (!input || typeof input !== 'object') {
    return {
      timezone: 'unknown',
      screen: '0x0',
      languages: 'unknown',
      pluginsCount: 0,
      fontsCount: 0,
      entropyScore: 0,
      jsDelayMs: 0,
    };
  }
  const timezone = String(input.timezone || 'unknown').slice(0, 64);
  const screen = String(input.screen || '0x0').slice(0, 32);
  const languages = String(input.languages || 'unknown').slice(0, 128);
  const pluginsCount = clamp(Number(input.pluginsCount || 0) || 0, 0, 128);
  const fontsCount = clamp(Number(input.fontsCount || 0) || 0, 0, 256);
  const entropyScore = clamp(Number(input.entropyScore || 0) || 0, 0, 100);
  const jsDelayMs = clamp(Number(input.jsDelayMs || 0) || 0, 0, 20000);
  return { timezone, screen, languages, pluginsCount, fontsCount, entropyScore, jsDelayMs };
}

function makeSessionKey(ip, fpHash) {
  return `shield:session:${ip}:${fpHash}`;
}

async function trackAttackMemory(env, ip, eventType, reason) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') return null;
  const key = `shield:attacks:ip:${ip}`;
  const prev = (await kvGetJson(env, key)) || {
    count: 0,
    last: 0,
    types: {},
    reasons: [],
  };
  prev.count = Number(prev.count || 0) + 1;
  prev.last = Date.now();
  prev.types[eventType] = Number(prev.types[eventType] || 0) + 1;
  const msg = String(reason || '').slice(0, 140);
  if (msg) {
    prev.reasons = Array.isArray(prev.reasons) ? prev.reasons : [];
    prev.reasons.push(msg);
    if (prev.reasons.length > 8) prev.reasons = prev.reasons.slice(-8);
  }
  await kvPutJson(env, key, prev, 14 * 24 * 3600);
  return prev;
}

function normalizeFpHash(value) {
  const candidate = String(value || '').trim().toLowerCase();
  return FP_HASH_RE.test(candidate) ? candidate : '';
}

function isTrustedAsnOrg(asOrg, env) {
  const org = String(asOrg || '').toLowerCase().trim();
  if (!org) return false;
  const trusted = String(env?.TRUSTED_ASN_ORGS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  if (!trusted.length) return false;
  return trusted.some((hint) => org.includes(hint));
}

function isHexSha256(value) {
  return /^[a-f0-9]{64}$/i.test(String(value || '').trim());
}

function isSensitiveAuthPath(pathLower) {
  if (SENSITIVE_AUTH_PATHS.has(pathLower)) return true;
  return (
    pathLower.endsWith('/login')
    || pathLower.includes('/auth/')
    || pathLower.includes('/token')
    || pathLower.includes('/signin')
  );
}

async function kvIncrementTtl(env, key, ttlSeconds) {
  if (!env?.SHIELD_KV) return 0;
  try {
    const safeTtl = Math.max(60, Number(ttlSeconds || 0));
    const current = Number((await env.SHIELD_KV.get(key)) || '0');
    const next = current + 1;
    await env.SHIELD_KV.put(key, String(next), { expirationTtl: safeTtl });
    return next;
  } catch {
    return 0;
  }
}

async function checkTokenBucketBurst(env, ip, fpHash, nowMs) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') {
    return { blocked: false, ipPerSec: 0, fpPerSec: 0 };
  }
  const secondBucket = Math.floor(nowMs / 1000);
  const ipKey = `shield:tb:ip:${ip}:${secondBucket}`;
  const fpKey = fpHash ? `shield:tb:fp:${fpHash}:${secondBucket}` : null;

  const [ipPerSec, fpPerSec] = await Promise.all([
    kvIncrementTtl(env, ipKey, 8),
    fpKey ? kvIncrementTtl(env, fpKey, 8) : Promise.resolve(0),
  ]);

  const blocked = ipPerSec > 35 || fpPerSec > 45;
  return { blocked, ipPerSec, fpPerSec };
}

async function trackAuthPressure(env, ip, fpHash, pathLower) {
  if (!env?.SHIELD_KV || !isSensitiveAuthPath(pathLower)) {
    return { active: false, hard: false, warn: false, ipCount: 0, fpCount: 0 };
  }
  const windowSlot = Math.floor(Date.now() / (5 * 60 * 1000));
  const ipKey = `shield:auth:ip:${ip}:${pathLower}:${windowSlot}`;
  const fpKey = fpHash ? `shield:auth:fp:${fpHash}:${pathLower}:${windowSlot}` : null;

  const [ipCount, fpCount] = await Promise.all([
    kvIncrementTtl(env, ipKey, 20 * 60),
    fpKey ? kvIncrementTtl(env, fpKey, 20 * 60) : Promise.resolve(0),
  ]);

  const hard = ipCount >= 20 || fpCount >= 25;
  const warn = ipCount >= 8 || fpCount >= 10;
  return { active: true, hard, warn, ipCount, fpCount };
}

function powFailKey(ip, fpHash) {
  return `shield:pow:fail:${ip}:${fpHash || 'nofp'}`;
}

async function getPowFailStreak(env, ip, fpHash) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') return 0;
  const data = await kvGetJson(env, powFailKey(ip, fpHash));
  return Number(data?.count || 0);
}

async function increasePowFailStreak(env, ip, fpHash) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') return 0;
  const key = powFailKey(ip, fpHash);
  const prev = (await kvGetJson(env, key)) || { count: 0, updatedAt: 0 };
  const next = { count: Number(prev.count || 0) + 1, updatedAt: Date.now() };
  await kvPutJson(env, key, next, 30 * 60);
  return next.count;
}

async function clearPowFailStreak(env, ip, fpHash) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') return;
  await env.SHIELD_KV.delete(powFailKey(ip, fpHash));
}

async function loadRuntimePolicy(env) {
  if (!env?.SHIELD_KV) return { ...DEFAULT_POLICY };
  try {
    const raw = await env.SHIELD_KV.get(POLICY_KEY, 'json');
    const data = raw && typeof raw === 'object' ? raw : {};
    return {
      protectEnabled: data.protectEnabled !== false,
      rateLimitEnabled: data.rateLimitEnabled !== false,
      attackBlockEnabled: data.attackBlockEnabled !== false,
      honeypotEnabled: data.honeypotEnabled !== false,
      aiCrawlerBlockEnabled: data.aiCrawlerBlockEnabled !== false,
      ddosBlockEnabled: data.ddosBlockEnabled !== false,
      vpnBlockEnabled: data.vpnBlockEnabled !== false,
      extraHoneypotPaths: Array.isArray(data.extraHoneypotPaths) ? data.extraHoneypotPaths.map((x) => String(x || '').toLowerCase().trim()).filter(Boolean) : [],
      extraVpnHints: Array.isArray(data.extraVpnHints) ? data.extraVpnHints.map((x) => String(x || '').toLowerCase().trim()).filter(Boolean) : [],
    };
  } catch {
    return { ...DEFAULT_POLICY };
  }
}

// ═══════════════════════════════════════════════════════════════════
//  Helper: emit block logs (reduces repetition)
// ═══════════════════════════════════════════════════════════════════
function emitBlockLogs(ctx, env, eventType, reason, baseDetails, signals, fpHash, ip, asn) {
  baseDetails._preventedBytes = estimatePreventedBytes({ headers: { get: () => null } }, signals);
  ctx.waitUntil(Promise.all([
    addPreventedTraffic(env, baseDetails._preventedBytes),
    sendDiscordWebhook(env, eventType, reason, baseDetails),
    sendExternalLog(env, eventType, reason, baseDetails),
    logToD1(env, eventType, reason, baseDetails),
    saveToR2(env, eventType, baseDetails),
    incrementKvStat(env, eventType === 'HONEYPOT' ? 'honeypot' : eventType === 'ATTACK' ? 'attack' : 'blocked'),
    incrementKvStat(env, 'total'),
    storeBehaviorProfile(env, { event: eventType, fpHash, ip, asn }),
    trackAttackMemory(env, ip, eventType, reason),
    updateThreatIntel(env, baseDetails, true),
  ]));
}

function applyPenaltyToDetails(baseDetails, penalty) {
  if (!penalty) return;
  baseDetails._penaltyLabel = penaltyLabel(penalty.level, penalty.permanent);
  baseDetails._penaltyPermanent = !!penalty.permanent;
  baseDetails._penaltyUntil = penalty.permanent ? 'permanent' : new Date(Number(penalty.until || 0) * 1000).toISOString();
}

// ═══════════════════════════════════════════════════════════════════
//  Main Worker Export
// ═══════════════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
   try {
    // Load remote lists (cached in memory + KV)
    await loadRemoteLists(env);
    await loadDynamicIpBlacklist(env);

    const url = new URL(request.url);
    const host = url.hostname.toLowerCase();
    const rayId = request.headers.get('cf-ray') || 'N/A';
    const colo = request.cf?.colo || 'N/A';
    const utcTime = new Date().toISOString();
    const nowMs = Date.now();
    const ip = getClientIp(request);
    const ua = request.headers.get('user-agent') || 'N/A';
    const method = request.method || 'N/A';
    const pathLower = url.pathname.toLowerCase();

    let runtimeWhitelistExtra = '';
    if (env?.SHIELD_KV) {
      try {
        const runtimeIps = await env.SHIELD_KV.get('shield:whitelist:extra', 'json');
        const parsed = Array.isArray(runtimeIps) ? runtimeIps : [];
        runtimeWhitelistExtra = parsed
          .map((value) => String(value || '').trim())
          .filter(Boolean)
          .join(',');
      } catch {}
    }
    const mergedWhitelistEnv = {
      ...env,
      IP_WHITELIST_EXTRA: [String(env?.IP_WHITELIST_EXTRA || '').trim(), runtimeWhitelistExtra].filter(Boolean).join(','),
    };
    const isWhitelistedIp = (candidateIp) => isIpWhitelisted(candidateIp, mergedWhitelistEnv);

    const publicAssetPaths = new Set(['/logo.webp', '/logo.png', '/logo.jpg', '/favicon.ico']);
    if ((method === 'GET' || method === 'HEAD') && publicAssetPaths.has(pathLower)) {
      const assetResponse = await fetch(request);
      const assetHeaders = new Headers(assetResponse.headers);
      securityHeaders(assetHeaders);
      assetHeaders.set('cache-control', 'public, max-age=86400');
      return new Response(assetResponse.body, {
        status: assetResponse.status,
        statusText: assetResponse.statusText,
        headers: assetHeaders,
      });
    }

    if (method === 'GET' && (pathLower === '/shield-stats' || pathLower === '/shield-stats/')) {
      const dashboardSession = await resolveDashboardSession(request, env);
      return new Response(htmlShieldStats(host, dashboardSession.ok ? dashboardSession.stats : null), {
        status: 200,
        headers: securityHeaders(new Headers({
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
        })),
      });
    }

    const adminResponse = await handleAdminRoutes(request, env, ip);
    if (adminResponse) {
      return adminResponse;
    }

    // ── Early silent block for already-blacklisted/suspended IPs ──
    // Skips entire detection pipeline, KV writes, and webhook spam
    // NOTE: active penalties/blacklist always override whitelist access.
    const earlyBlacklist = await getIpBlacklistStatus(env, ip);
    if (earlyBlacklist.blocked) {
      const silentReason = earlyBlacklist.source.includes('permanent')
        ? 'Permanently suspended' : 'IP address suspended';
      ctx.waitUntil(logToD1(env, 'HARD_BLOCKED', 'Silent re-block (' + earlyBlacklist.source + ')', {
        ip, ua, method, host, path: url.pathname + url.search,
        rayId, country: request.cf?.country || 'N/A',
        asOrg: request.cf?.asOrganization || 'N/A',
        asn: String(request.cf?.asn || 'N/A'),
        colo, utcTime,
        tlsVersion: request.cf?.tlsVersion || 'N/A',
        httpVersion: request.cf?.httpProtocol || 'N/A',
        threatScore: 100,
      }));
      return new Response(htmlSuspended(host, rayId, silentReason), {
        status: 403,
        headers: securityHeaders(new Headers({
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
        })),
      });
    }

    const runtimePolicy = await loadRuntimePolicy(env);

    const referer = request.headers.get('referer') || 'N/A';
    const acceptLanguage = request.headers.get('accept-language') || 'N/A';
    const country = request.cf?.country || 'N/A';
    const asOrg = request.cf?.asOrganization || 'N/A';
    const asn = String(request.cf?.asn || 'N/A');
    const tlsVersion = request.cf?.tlsVersion || 'N/A';
    const httpVersion = request.cf?.httpProtocol || 'N/A';
    const cookies = parseCookies(request.headers.get('cookie'));
    const clearShieldCookies = (headers) => {
      headers.append('set-cookie', COOKIE_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_EXP_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_SIG_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_FP_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_RISK_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_RECHECK_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax');
      return headers;
    };
    const verifiedFlag = cookies[COOKIE_NAME] === '1';
    const cookieExp = Number(cookies[COOKIE_EXP_NAME] || 0);
    const cookieSig = cookies[COOKIE_SIG_NAME] || '';
    const cookieFp = String(cookies[COOKIE_FP_NAME] || '');
    const recheckUntil = Number(cookies[COOKIE_RECHECK_NAME] || 0);
    const nowSec = Math.floor(nowMs / 1000);
    const isExpired = cookieExp > 0 && nowSec > cookieExp;
    let verified = false;
    if (verifiedFlag && !isExpired && cookieSig && cookieFp) {
      const secret = getSigningSecret(env);
      const tokenData = ip + ':' + cookieExp + ':' + cookieFp;
      verified = await hmacVerify(secret, tokenData, cookieSig);
    }
    const cookieFpValidated = normalizeFpHash(cookies[COOKIE_FP_NAME]);
    const fpHash = cookieFpValidated || await deriveRequestFingerprint(request, ip);
    const behaviorRisk = await loadBehaviorRisk(env, fpHash, asn, country);
    behaviorRisk._fpHash = fpHash;
    const ipReputation = await loadIpReputation(env, ip);
    const trustedAsnOrg = isTrustedAsnOrg(asOrg, env);
    const signals = buildDetectionSignals(request, ip, nowMs, behaviorRisk);
    const {
      suspicious, headless, vpn: vpnProxy, aiCrawler,
      spam, hardBlocked, attackFlags, ddosSuspect,
      clientType, headerPresenceScore, ipRate, prefixRate, ipPrefix,
      isBotFarm, countryAnomaly, tlsScore, tlsSignals,
      fpSpam, fpHardBlocked, patternScore,
    } = signals;
    const runtimeVpnProxy = vpnProxy || runtimePolicy.extraVpnHints.some((hint) => String(asOrg || '').toLowerCase().includes(hint));
    const baseThreatScore = computeThreatScore(request, signals);
    const ipRepInfluence = clamp(Number(ipReputation.score || 0), 0, 100);
    const threatScore = clamp(
      Math.max(baseThreatScore, Math.round(baseThreatScore * 0.75 + ipRepInfluence * 0.25)),
      0,
      100
    );
    const escalationAction = determineEscalation(threatScore, signals);

    const baseDetails = {
      ip, ua, method, referer, acceptLanguage,
      host, path: url.pathname + url.search,
      rayId, country, asOrg, asn, colo, utcTime,
      tlsVersion, httpVersion, threatScore, fpHash,
      _suspicious: suspicious, _headless: headless,
      _vpn: runtimeVpnProxy, _aiCrawler: aiCrawler,
      _ddosSuspect: ddosSuspect, _clientType: clientType,
      _headerPresenceScore: headerPresenceScore,
      _ipRate: ipRate, _prefixRate: prefixRate, _ipPrefix: ipPrefix,
      _spam: spam, _attackFlags: attackFlags,
      _isBotFarm: isBotFarm, _countryAnomaly: countryAnomaly,
      _tlsScore: tlsScore, _tlsSignals: tlsSignals,
      _ipRepScore: ipReputation.score, _ipRepTrusted: ipReputation.trusted,
      _fpSpam: fpSpam, _patternScore: patternScore,
      _baseThreatScore: baseThreatScore,
      _ipRepInfluence: ipRepInfluence,
      _trustedAsnOrg: trustedAsnOrg,
      _escalation: escalationAction,
      _fpHardBlocked: fpHardBlocked,
    };

    const proxyWithMaintenanceFallback = async (req, contextLabel = 'origin_proxy') => {
      // ── Multi-tenant origin resolution ──
      const siteResult = await lookupSite(env, host);
      const originReq = siteResult.found
        ? buildOriginRequest(req, siteResult.site)
        : req;

      try {
        const response = await fetch(originReq);
        if (response.status >= 500) {
          const alreadyKnown = isOriginKnownDown(host);
          markOriginDown(host);
          // Always log to D1, only webhook on first detection
          const tasks = [logErrorToD1(env, 'Origin responded with ' + response.status, `${contextLabel}_upstream_5xx`, baseDetails)];
          if (!alreadyKnown) {
            tasks.push(sendDiscordWebhook(env, 'ERROR', 'Origin returned ' + response.status + ' (maintenance fallback)', baseDetails));
          }
          ctx.waitUntil(Promise.all(tasks));
          return new Response(htmlServiceDown(host, rayId), {
            status: 502,
            headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
          });
        }

        const newHeaders = new Headers(response.headers);
        securityHeaders(newHeaders);
        return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
      } catch (err) {
        const alreadyKnown = isOriginKnownDown(host);
        markOriginDown(host);
        const tasks = [logErrorToD1(env, 'Origin fetch failed: ' + err.message, err.stack, baseDetails)];
        if (!alreadyKnown) {
          tasks.push(sendDiscordWebhook(env, 'ERROR', 'Origin fetch failed: ' + err.message, baseDetails));
        }
        ctx.waitUntil(Promise.all(tasks));
        return new Response(htmlServiceDown(host, rayId), {
          status: 502,
          headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
        });
      }
    };

    const tokenBucket = await checkTokenBucketBurst(env, ip, fpHash, nowMs);
    baseDetails._ipPerSec = tokenBucket.ipPerSec;
    baseDetails._fpPerSec = tokenBucket.fpPerSec;

    if (runtimePolicy.rateLimitEnabled && tokenBucket.blocked && !isWhitelistedIp(ip)) {
      const penalty = await escalateIpPenalty(env, ip, 'Token-bucket burst threshold exceeded', baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'RATE_LIMITED', 'Token-bucket burst threshold exceeded', baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlRateLimited(host, rayId), {
        status: 429,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '45' })),
      });
    }

    const attackMemory = env?.SHIELD_KV ? await kvGetJson(env, `shield:attacks:ip:${ip}`) : null;
    if (attackMemory && Number(attackMemory.count || 0) >= 25 && (Date.now() - Number(attackMemory.last || 0)) < 24 * 3600 * 1000) {
      const penalty = await setPermanentPenalty(env, ip, 'Persistent offender auto-block from attack memory', baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'HARD_BLOCKED', 'Persistent offender auto-block', baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlSuspended(host, rayId, 'Persistent abusive activity detected'), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    ctx.waitUntil(emitDeploymentEventIfNeeded(env, baseDetails));

    // ── Attack pattern hard block ──
    if (runtimePolicy.attackBlockEnabled && attackFlags.length > 0) {
      const penalty = await escalateIpPenalty(env, ip, 'Attack signature: ' + attackFlags.join(','), baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'ATTACK', 'Attack detected: ' + attackFlags.join(', '), baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlAttackBlocked(host, rayId, attackFlags.join(', ')), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    // ── Smart honeypot endpoints (instant permanent ban) ──
    const instantBanHoneypots = new Set(['/admin-test', '/internal-admin', '/.git/config', '/wp-admin.php', '/.env', '/debug', '/wp-login.php', '/phpmyadmin', '/admin/config', '/.aws/credentials', '/server-status']);
    for (const extraPath of runtimePolicy.extraHoneypotPaths) {
      if (String(extraPath || '').startsWith('/')) instantBanHoneypots.add(String(extraPath));
    }
    if (runtimePolicy.honeypotEnabled && instantBanHoneypots.has(pathLower)) {
      if (!verified) {
        const penalty = await setPermanentPenalty(env, ip, 'Instant honeypot endpoint: ' + pathLower, baseDetails);
        applyPenaltyToDetails(baseDetails, penalty);
        emitBlockLogs(ctx, env, 'HONEYPOT', 'Instant-ban honeypot triggered: ' + pathLower, baseDetails, signals, fpHash, ip, asn);
        return new Response(htmlHoneypotTriggered(host, rayId), {
          status: 403,
          headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
        });
      }

      const challengeBody = htmlChallenge(host, rayId, colo, utcTime, threatScore);
      const challengeHeaders = clearShieldCookies(securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })));
      challengeHeaders.append('set-cookie', COOKIE_RISK_NAME + '=' + String(Math.max(60, Number(threatScore || 0))) + '; Path=/; Max-Age=120; HttpOnly; Secure; SameSite=Lax');
      ctx.waitUntil(Promise.all([
        sendDiscordWebhook(env, 'CHALLENGED', 'Verified session hit honeypot endpoint: ' + pathLower, baseDetails),
        logToD1(env, 'CHALLENGED', 'Verified session hit honeypot endpoint: ' + pathLower, baseDetails),
      ]));
      return new Response(challengeBody, { status: 403, headers: challengeHeaders });
    }

    // ── Honeypot trap from LISTS ──
    const honeypotPaths = runtimePolicy.honeypotEnabled
      ? [...new Set([...(LISTS.honeypot_paths || []), ...(runtimePolicy.extraHoneypotPaths || [])])]
      : [];
    const ignoredHoneypotPaths = new Set(['/test']);
    const effectiveHoneypotPaths = honeypotPaths
      .map((p) => String(p || '').toLowerCase().trim())
      .filter((p) => p.startsWith('/') && !ignoredHoneypotPaths.has(p));
    if (runtimePolicy.honeypotEnabled && effectiveHoneypotPaths.some(p => pathLower === p || pathLower.startsWith(p + '/'))) {
      if (!verified) {
        const penalty = await escalateIpPenalty(env, ip, 'Honeypot path: ' + url.pathname, baseDetails);
        applyPenaltyToDetails(baseDetails, penalty);
        emitBlockLogs(ctx, env, 'HONEYPOT', 'Honeypot triggered: ' + url.pathname, baseDetails, signals, fpHash, ip, asn);
        return new Response(htmlHoneypotTriggered(host, rayId), {
          status: 403,
          headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
        });
      }

      const challengeBody = htmlChallenge(host, rayId, colo, utcTime, threatScore);
      const challengeHeaders = clearShieldCookies(securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })));
      challengeHeaders.append('set-cookie', COOKIE_RISK_NAME + '=' + String(Math.max(50, Number(threatScore || 0))) + '; Path=/; Max-Age=120; HttpOnly; Secure; SameSite=Lax');
      ctx.waitUntil(Promise.all([
        sendDiscordWebhook(env, 'CHALLENGED', 'Verified session hit honeypot path: ' + url.pathname, baseDetails),
        logToD1(env, 'CHALLENGED', 'Verified session hit honeypot path: ' + url.pathname, baseDetails),
      ]));
      return new Response(challengeBody, { status: 403, headers: challengeHeaders });
    }

    const authPressure = await trackAuthPressure(env, ip, fpHash, pathLower);
    if (authPressure.active) {
      baseDetails._authPressureIp = authPressure.ipCount;
      baseDetails._authPressureFp = authPressure.fpCount;
      baseDetails._authPressureWarn = authPressure.warn;
      if (runtimePolicy.rateLimitEnabled && authPressure.hard && !isWhitelistedIp(ip)) {
        const penalty = await escalateIpPenalty(env, ip, `Bruteforce pressure on ${pathLower}`, baseDetails);
        applyPenaltyToDetails(baseDetails, penalty);
        emitBlockLogs(ctx, env, 'RATE_LIMITED', 'Bruteforce pressure detected on ' + pathLower, baseDetails, signals, fpHash, ip, asn);
        return new Response(htmlRateLimited(host, rayId), {
          status: 429,
          headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '120' })),
        });
      }
    }

    // ── Fake responses for obvious bots/scrapers ──
    if ((clientType === 'bot' || clientType === 'crawler' || clientType === 'robot') && !url.pathname.startsWith('/__')) {
      if (pathLower.startsWith('/api') || pathLower.includes('admin') || pathLower.endsWith('.php')) {
        const fakePayload = {
          ok: true, status: 'queued',
          request_id: crypto.randomUUID(),
          message: 'Request accepted',
          data: { queue_position: Math.floor(Math.random() * 100) + 1 },
        };
        return new Response(JSON.stringify(fakePayload), {
          status: 200,
          headers: securityHeaders(new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })),
        });
      }
    }

    // ── API Routes (auth required) ──
    const apiAuth = (route, allowedMethod) => {
      if (url.pathname !== route) return false;
      if (allowedMethod && method !== allowedMethod && !(allowedMethod === 'PUT|POST' && (method === 'PUT' || method === 'POST'))) return false;
      const apiKey = env?.STATS_API_KEY;
      if (apiKey) {
        const auth = request.headers.get('authorization');
        if (auth !== 'Bearer ' + apiKey) return 'unauthorized';
      }
      return true;
    };

    // Stats
    if (apiAuth('/__shield/stats', 'GET') === true) return handleStatsApi(env);
    if (apiAuth('/__shield/stats', 'GET') === 'unauthorized') return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
    // List Reload
    if (apiAuth('/__shield/reload', 'POST') === true) return handleListReload(env);
    if (apiAuth('/__shield/reload', 'POST') === 'unauthorized') return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
    // Blacklist Reload
    if (apiAuth('/__shield/blacklist/reload', 'POST') === true) return handleBlacklistReload(env);
    if (apiAuth('/__shield/blacklist/reload', 'POST') === 'unauthorized') return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
    // Blacklist View
    if (url.pathname === '/__shield/blacklist' && method === 'GET') {
      const apiKey = env?.STATS_API_KEY;
      if (apiKey && request.headers.get('authorization') !== 'Bearer ' + apiKey) return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
      return handleBlacklistView();
    }
    // Blacklist Update
    if (url.pathname === '/__shield/blacklist' && (method === 'PUT' || method === 'POST')) {
      const apiKey = env?.STATS_API_KEY;
      if (apiKey && request.headers.get('authorization') !== 'Bearer ' + apiKey) return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
      try { return await handleBlacklistUpdate(env, request); } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 400, headers: securityHeaders(new Headers({ 'content-type': 'application/json' })) });
      }
    }
    // List Update
    if (url.pathname === '/__shield/lists' && (method === 'PUT' || method === 'POST')) {
      const apiKey = env?.STATS_API_KEY;
      if (apiKey && request.headers.get('authorization') !== 'Bearer ' + apiKey) return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
      try { return await handleListUpdate(env, request); } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 400, headers: securityHeaders(new Headers({ 'content-type': 'application/json' })) });
      }
    }
    // List View
    if (url.pathname === '/__shield/lists' && method === 'GET') {
      const apiKey = env?.STATS_API_KEY;
      if (apiKey && request.headers.get('authorization') !== 'Bearer ' + apiKey) return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
      return handleListView();
    }

    // Unblacklist / Clear Penalty
    if (apiAuth('/__shield/unblacklist', 'POST') === true) return handleUnblacklist(env, request, ip);
    if (apiAuth('/__shield/unblacklist', 'POST') === 'unauthorized') return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });

    // Runtime Extra Whitelist (KV-backed)
    if (apiAuth('/__shield/whitelist-extra', 'GET') === true) return handleWhitelistExtraView(env);
    if (apiAuth('/__shield/whitelist-extra', 'GET') === 'unauthorized') return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
    if (apiAuth('/__shield/whitelist-extra', 'POST') === true) return handleWhitelistExtraUpdate(env, request);
    if (apiAuth('/__shield/whitelist-extra', 'POST') === 'unauthorized') return new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });

    // ── PoW Challenge endpoint ──
    if (url.pathname === '/__challenge' && method === 'GET') {
      const challengeBlacklist = await getIpBlacklistStatus(env, ip);
      if (challengeBlacklist.blocked) {
        const headers = clearShieldCookies(securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })));
        return new Response(JSON.stringify({ ok: false, error: 'Access suspended' }), {
          status: 403,
          headers,
        });
      }
      const reqCookies = parseCookies(request.headers.get('cookie'));
      const risk = Number(reqCookies[COOKIE_RISK_NAME] || 0);
      const dynamicDifficulty = Math.max(2, Math.min(7, POW_DIFFICULTY + (risk >= 85 ? 3 : risk >= 65 ? 2 : risk >= 40 ? 1 : 0)));
      const failStreak = await getPowFailStreak(env, ip, fpHash);
      const streakBonus = failStreak >= 10 ? 3 : failStreak >= 6 ? 2 : failStreak >= 3 ? 1 : 0;
      const adjustedDifficulty = clamp(dynamicDifficulty + streakBonus, 2, 7);
      const challengeType = (risk >= 75 || failStreak >= 6) ? 'pow-hard' : (risk >= 45 || failStreak >= 3 ? 'pow' : 'pow-lite');
      const prefix = crypto.randomUUID();
      const challengeId = crypto.randomUUID();
      const challengeFp = normalizeFpHash(url.searchParams.get('fp') || request.headers.get('x-shield-fp'));
      const ttlSeconds = clamp(
        risk >= 80 ? 30 : risk >= 60 ? 45 : risk >= 45 ? 75 : CHALLENGE_NONCE_TTL,
        CHALLENGE_MIN_TTL,
        CHALLENGE_MAX_TTL
      );
      const issuedAt = Date.now();
      const prefixHash = await sha256(prefix);
      const secret = getSigningSecret(env);
      const sigPayload = `${challengeId}:${prefixHash}:${ip}:${issuedAt}:${ttlSeconds}:${challengeFp || 'nofp'}`;
      const challengeSig = await hmacSign(secret, sigPayload);

      if (env?.SHIELD_KV) {
        await kvPutJson(env, `shield:challenge:${challengeId}`, {
          challengeId, ip,
          difficulty: adjustedDifficulty,
          challengeType,
          prefixHash,
          issuedAt,
          ttlSeconds,
          fpHash: challengeFp || '',
          challengeSig,
        }, ttlSeconds);
      }

      return new Response(JSON.stringify({
        prefix,
        difficulty: adjustedDifficulty,
        challengeType,
        challengeId,
        challengeSig,
        issuedAt,
        expiresIn: ttlSeconds,
        failStreak,
      }), {
        headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
      });
    }

    // ── Verification endpoint (with behavioral analysis + honeypot check) ──
    if (url.pathname === '/__verify' && method === 'POST') {
      const verifyBlacklist = await getIpBlacklistStatus(env, ip);
      if (verifyBlacklist.blocked) {
        const headers = clearShieldCookies(securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })));
        return new Response(JSON.stringify({ ok: false, error: 'Access suspended' }), {
          status: 403,
          headers,
        });
      }
      let valid = false;
      let verifyFpHash = '';
      let behaviorResult = { behaviorScore: 0, isHuman: null, signals: [] };
      let honeypotResult = { honeypotTriggered: false, honeypotScore: 0 };
      const requestOrigin = String(request.headers.get('origin') || '');
      const requestReferer = String(request.headers.get('referer') || '');
      const sameOriginVerify = requestOrigin === `https://${host}` || requestReferer.startsWith(`https://${host}/`);
      try {
        const contentType = request.headers.get('content-type') || '';
        if (!contentType.toLowerCase().includes('application/json')) {
          return new Response(JSON.stringify({ ok: false, error: 'Unsupported content type' }), {
            status: 415,
            headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
          });
        }

        const contentLength = Number(request.headers.get('content-length') || 0);
        if (Number.isFinite(contentLength) && contentLength > 32768) {
          return new Response(JSON.stringify({ ok: false, error: 'Payload too large' }), {
            status: 413,
            headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
          });
        }

        const body = await request.json();
        if (!body || typeof body !== 'object') {
          throw new Error('invalid body');
        }
        const {
          prefix, nonce, hash,
          challengeId, challengeType, challengeSig,
          challengeDifficulty,
          challengeIssuedAt, challengeExpiresIn,
          fpHash: bodyFpHash, behavior, honeypot, client,
          __RYZEON_SECRET: leakedTrapSecret,
        } = body;
        verifyFpHash = normalizeFpHash(bodyFpHash);
        if (!verifyFpHash) {
          verifyFpHash = await deriveRequestFingerprint(request, ip);
        }

        const hasValidChallengeId = UUID_RE.test(String(challengeId || ''));
        const hasValidPrefix = UUID_RE.test(String(prefix || ''));
        const hasValidHash = isHexSha256(hash);
        const hasValidChallengeSig = !challengeSig || SIG_RE.test(String(challengeSig || ''));
        const nonceStr = String(nonce ?? '').trim();
        const hasValidNonce = /^\d{1,20}$/.test(nonceStr);

        if (!hasValidChallengeId || !hasValidPrefix || !hasValidHash || !hasValidNonce || !hasValidChallengeSig) {
          throw new Error('invalid challenge payload');
        }

        if (typeof leakedTrapSecret === 'string' && leakedTrapSecret.length > 0) {
          const penalty = await setPermanentPenalty(env, ip, 'Canary variable exfiltration (__RYZEON_SECRET)', baseDetails);
          applyPenaltyToDetails(baseDetails, penalty);
          ctx.waitUntil(Promise.all([
            sendDiscordWebhook(env, 'HONEYPOT_FORM', 'Canary JS variable leaked by client payload', baseDetails),
            logToD1(env, 'HONEYPOT_FORM', 'Canary variable leaked', baseDetails),
            incrementKvStat(env, 'honeypot'),
            incrementKvStat(env, 'total'),
            storeBehaviorProfile(env, { event: 'HONEYPOT', fpHash: verifyFpHash || fpHash, ip, asn }),
            trackAttackMemory(env, ip, 'HONEYPOT_FORM', 'Canary variable leaked'),
          ]));
          return new Response(JSON.stringify({ ok: false, error: 'Blocked' }), {
            status: 403,
            headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
          });
        }

        // Score behavioral data from client
        behaviorResult = scoreBehavior(behavior);
        honeypotResult = scoreHoneypot(honeypot);

        // If honeypot form fields are filled → instant ban
        if (runtimePolicy.honeypotEnabled && honeypotResult.honeypotTriggered) {
          const penalty = await setPermanentPenalty(env, ip, 'Honeypot form field filled', baseDetails);
          applyPenaltyToDetails(baseDetails, penalty);
          ctx.waitUntil(Promise.all([
            sendDiscordWebhook(env, 'HONEYPOT_FORM', 'Hidden form honeypot triggered', baseDetails),
            logToD1(env, 'HONEYPOT_FORM', 'Hidden form field filled by bot', baseDetails),
            incrementKvStat(env, 'honeypot'),
            incrementKvStat(env, 'total'),
            storeBehaviorProfile(env, { event: 'HONEYPOT', fpHash: verifyFpHash || fpHash, ip, asn }),
            trackAttackMemory(env, ip, 'HONEYPOT_FORM', 'Hidden form honeypot triggered'),
          ]));
          return new Response(JSON.stringify({ ok: false, error: 'Blocked' }), {
            status: 403,
            headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
          });
        }

        let requiredDifficulty = POW_DIFFICULTY;
        let requiredType = 'pow';
        let challengeFpMismatch = false;
        let challengeReplaySuspect = false;
        let challengeValidated = false;
        let powExpected = '';
        let powTypeOk = true;
        let powHashOk = false;
        let powDifficultyOk = false;

        if (env?.SHIELD_KV && challengeId) {
          const stored = await kvGetJson(env, `shield:challenge:${challengeId}`);
          const storedIssuedAt = Number(stored?.issuedAt || 0);
          const storedTtl = clamp(Number(stored?.ttlSeconds || CHALLENGE_NONCE_TTL), CHALLENGE_MIN_TTL, CHALLENGE_MAX_TTL);
          const fresh = stored
            && Number.isFinite(storedIssuedAt)
            && storedIssuedAt > 0
            && (Date.now() - storedIssuedAt) <= (storedTtl * 1000);
          const prefixHash = await sha256(prefix);
          const expectedSigData = `${challengeId}:${prefixHash}:${ip}:${storedIssuedAt}:${storedTtl}:${stored?.fpHash || 'nofp'}`;
          const providedSig = String(challengeSig || '').trim();
          const signatureOk = stored?.challengeSig
            ? !!providedSig
              && String(stored.challengeSig) === providedSig
              && await hmacVerify(getSigningSecret(env), expectedSigData, providedSig)
            : true;
          challengeFpMismatch = !!stored?.fpHash && stored.fpHash !== verifyFpHash;
          if (fresh && stored.ip === ip && stored.prefixHash === prefixHash && stored.challengeId === challengeId && signatureOk && !challengeFpMismatch) {
            requiredDifficulty = Number(stored.difficulty || requiredDifficulty);
            requiredType = String(stored.challengeType || requiredType);
            challengeValidated = true;
            await env.SHIELD_KV.delete(`shield:challenge:${challengeId}`);
          } else {
            const fallbackIssuedAt = Number(challengeIssuedAt || 0);
            const fallbackTtl = clamp(Number(challengeExpiresIn || CHALLENGE_NONCE_TTL), CHALLENGE_MIN_TTL, CHALLENGE_MAX_TTL);
            const fallbackFresh = Number.isFinite(fallbackIssuedAt)
              && fallbackIssuedAt > 0
              && (Date.now() - fallbackIssuedAt) <= (fallbackTtl * 1000);
            const fallbackSigDataWithFp = `${challengeId}:${prefixHash}:${ip}:${fallbackIssuedAt}:${fallbackTtl}:${verifyFpHash || 'nofp'}`;
            const fallbackSigDataNoFp = `${challengeId}:${prefixHash}:${ip}:${fallbackIssuedAt}:${fallbackTtl}:nofp`;
            const providedSig = String(challengeSig || '').trim();
            const fallbackSigOk = !!providedSig && fallbackFresh && (
              await hmacVerify(getSigningSecret(env), fallbackSigDataWithFp, providedSig)
              || await hmacVerify(getSigningSecret(env), fallbackSigDataNoFp, providedSig)
            );

            let fallbackReplayUsed = false;
            if (fallbackSigOk && env?.SHIELD_KV) {
              const replayKey = `shield:challenge:usedsig:${providedSig}`;
              fallbackReplayUsed = !!(await env.SHIELD_KV.get(replayKey));
              if (!fallbackReplayUsed) {
                try {
                  await env.SHIELD_KV.put(replayKey, '1', { expirationTtl: fallbackTtl });
                } catch { /* KV write limit — proceed with HMAC-only validation */ }
              }
            }

            if (fallbackSigOk && !fallbackReplayUsed) {
              requiredDifficulty = clamp(Number(challengeDifficulty || POW_DIFFICULTY), 2, 7);
              requiredType = String(challengeType || 'pow');
              challengeValidated = true;
            } else {
              challengeReplaySuspect = true;
              if (stored) await env.SHIELD_KV.delete(`shield:challenge:${challengeId}`);
              requiredDifficulty = 99;
            }
          }
        } else if (env?.SHIELD_KV) {
          challengeReplaySuspect = true;
          requiredDifficulty = 99;
        }

        if (prefix && nonce !== undefined && hash) {
          const data = prefix + ':' + nonce;
          const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data));
          powExpected = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
          powTypeOk = !challengeType || String(challengeType) === requiredType;
          powHashOk = powExpected === hash;
          powDifficultyOk = hash.startsWith('0'.repeat(requiredDifficulty));
          valid = challengeValidated && powTypeOk && powHashOk && powDifficultyOk;
        }

        // If behavior score is very high (likely bot), invalidate even correct PoW
        if (valid && behaviorResult.behaviorScore >= 25) {
          valid = false;
          baseDetails._behaviorRejected = true;
        }

        const clientSnapshot = normalizeClientSnapshot(client);
        const uaHash = await sha256((ua || '').slice(0, 512));
        let sessionDrift = false;
        if (env?.SHIELD_KV && verifyFpHash) {
          const sessKey = makeSessionKey(ip, verifyFpHash);
          const prevSession = await kvGetJson(env, sessKey);
          if (prevSession) {
            sessionDrift = (
              prevSession.uaHash !== uaHash
              || prevSession.screen !== clientSnapshot.screen
              || prevSession.timezone !== clientSnapshot.timezone
            );
          }
          await kvPutJson(env, sessKey, {
            uaHash,
            screen: clientSnapshot.screen,
            timezone: clientSnapshot.timezone,
            languages: clientSnapshot.languages,
            updatedAt: Date.now(),
          }, 24 * 3600);
        }

        const fpMismatchFactor = challengeFpMismatch ? 1 : 0;
        const behaviorBotFactor = behaviorResult.behaviorScore >= 18 ? 1 : behaviorResult.behaviorScore >= 10 ? 0.5 : 0;
        const tlsWeirdFactor = tlsScore >= 12 || tlsSignals.includes('old_tls') || tlsSignals.includes('http10') ? 1 : 0;
        const ipBadFactor = ipReputation.score >= 50 ? 1 : ipReputation.score >= 25 ? 0.5 : 0;
        const lowEntropyFactor = clientSnapshot.entropyScore < 20 ? 1 : 0;
        const fastJsFactor = clientSnapshot.jsDelayMs > 0 && clientSnapshot.jsDelayMs < 50 ? 1 : 0;
        const sessionDriftFactor = sessionDrift ? 1 : 0;

        const verificationRiskScore =
          (fpMismatchFactor * 40)
          + (behaviorBotFactor * 35)
          + (tlsWeirdFactor * 20)
          + (ipBadFactor * 25)
          + (lowEntropyFactor * 30)
          + (fastJsFactor * 40)
          + (sessionDriftFactor * 50)
          + (challengeReplaySuspect ? 50 : 0);

        const baselineThreat = clamp(Number(baseDetails.threatScore || 0), 0, 100);
        const behaviorThreat = clamp((Number(behaviorResult.behaviorScore || 0) * 3) + Number(honeypotResult.honeypotScore || 0), 0, 100);
        const verifyThreat = clamp(Number(verificationRiskScore || 0), 0, 100);
        const combinedThreat = clamp(Math.max(baselineThreat, behaviorThreat, verifyThreat), 0, 100);

        baseDetails.threatScore = combinedThreat;
        baseDetails._baselineThreatScore = baselineThreat;
        baseDetails._behaviorThreatScore = behaviorThreat;
        baseDetails._verifyThreatScore = verifyThreat;

        baseDetails._verifyRiskScore = verificationRiskScore;
        baseDetails._sessionDrift = sessionDrift;
        baseDetails._entropyScore = clientSnapshot.entropyScore;
        baseDetails._jsDelayMs = clientSnapshot.jsDelayMs;
        baseDetails._fpMismatch = challengeFpMismatch;
        baseDetails._challengeReplay = challengeReplaySuspect;

        if (valid && verificationRiskScore >= 60) {
          valid = false;
          baseDetails._riskRejected = true;
        }

        if (valid && runtimePolicy.vpnBlockEnabled && runtimeVpnProxy && !trustedAsnOrg && !isWhitelistedIp(ip)) {
          valid = false;
          baseDetails._vpnRejected = true;
          baseDetails._verifyFailCode = 'vpn_proxy_rejected';
        }

        const lowRiskSoftPass = (
          !valid
          && challengeValidated
          && !challengeReplaySuspect
          && !challengeFpMismatch
          && verificationRiskScore <= 20
          && behaviorResult.behaviorScore <= 8
          && !suspicious
          && !headless
          && !spam
          && !fpSpam
        );
        if (lowRiskSoftPass) {
          valid = true;
          baseDetails._powSoftPass = true;
        }

        if (!valid) {
          let failCode = 'pow_unknown';
          if (baseDetails._verifyMalformed) failCode = 'verify_malformed';
          else if (!challengeValidated) failCode = 'challenge_state_invalid';
          else if (!powTypeOk) failCode = 'pow_type_mismatch';
          else if (!powHashOk) failCode = 'pow_hash_mismatch';
          else if (!powDifficultyOk) failCode = 'pow_difficulty_not_met';
          if (challengeReplaySuspect) failCode = 'challenge_replay_or_expired';
          if (baseDetails._behaviorRejected) failCode = 'behavior_rejected';
          if (baseDetails._riskRejected) failCode = 'risk_rejected';
          baseDetails._verifyFailCode = failCode;
        }
      } catch (err) {
        baseDetails._verifyMalformed = true;
        const errTag = clip(String(err?.message || err || 'unknown').replace(/\s+/g, '_'), 36);
        baseDetails._verifyFailCode = `verify_exception:${errTag}`;
      }

      const emergencyCleanPass = (
        !valid
        && sameOriginVerify
        && !baseDetails._challengeReplay
        && !baseDetails._riskRejected
        && !baseDetails._behaviorRejected
        && Number(baseDetails.threatScore || 0) <= 10
        && behaviorResult.behaviorScore <= 8
        && !suspicious
        && !headless
        && !spam
        && !fpSpam
      );
      if (emergencyCleanPass) {
        valid = true;
        baseDetails._powSoftPass = 'emergency_clean';
      }

      if (!valid) {
        const failCode = baseDetails._verifyFailCode
          || (baseDetails._challengeReplay ? 'challenge_replay_or_expired'
            : baseDetails._riskRejected ? 'risk_rejected'
            : baseDetails._vpnRejected ? 'vpn_proxy_rejected'
            : baseDetails._behaviorRejected ? 'behavior_rejected'
            : baseDetails._verifyMalformed ? 'verify_malformed'
            : 'pow_unknown');
        const failReason = baseDetails._vpnRejected
          ? 'VPN/Proxy verification denied [' + failCode + ']'
          : 'PoW validation failed [' + failCode + ']';
        const failEventType = baseDetails._vpnRejected ? 'VPN_BLOCKED' : 'FAILED';
        const failStatKey = baseDetails._vpnRejected ? 'blocked' : 'failed';
        ctx.waitUntil(Promise.all([
          sendDiscordWebhookDelayed(env, failEventType, failReason, baseDetails, 3000),
          sendExternalLog(env, failEventType, failReason, baseDetails),
          logToD1(env, failEventType, failReason, baseDetails),
          incrementKvStat(env, failStatKey),
          incrementKvStat(env, 'total'),
          storeBehaviorProfile(env, { event: failEventType, fpHash: verifyFpHash || baseDetails.fpHash, ip, asn }),
          trackAttackMemory(env, ip, failEventType, failReason),
          increasePowFailStreak(env, ip, verifyFpHash || baseDetails.fpHash),
        ]));
        return new Response(JSON.stringify({ ok: false, error: baseDetails._vpnRejected ? 'VPN/Proxy denied' : 'Invalid proof-of-work' }), {
          status: 403,
          headers: securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })),
        });
      }

      const secret = getSigningSecret(env);
      const exp = Math.floor(nowMs / 1000) + COOKIE_MAX_AGE;
      const safeFp = normalizeFpHash(verifyFpHash) || (await deriveRequestFingerprint(request, ip));
      const verifyBlacklistAfterValidation = await getIpBlacklistStatus(env, ip);
      if (verifyBlacklistAfterValidation.blocked) {
        const denyHeaders = clearShieldCookies(securityHeaders(new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store' })));
        return new Response(JSON.stringify({ ok: false, error: 'Access suspended' }), {
          status: 403,
          headers: denyHeaders,
        });
      }
      const tokenData = ip + ':' + exp + ':' + safeFp;
      const sig = await hmacSign(secret, tokenData);

      const headers = securityHeaders(new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }));
      headers.append('set-cookie', COOKIE_NAME + '=1; Path=/; Max-Age=' + COOKIE_MAX_AGE + '; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_EXP_NAME + '=' + exp + '; Path=/; Max-Age=' + COOKIE_MAX_AGE + '; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_SIG_NAME + '=' + sig + '; Path=/; Max-Age=' + COOKIE_MAX_AGE + '; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_FP_NAME + '=' + safeFp + '; Path=/; Max-Age=' + COOKIE_MAX_AGE + '; HttpOnly; Secure; SameSite=Lax');
      headers.append('set-cookie', COOKIE_RECHECK_NAME + '=' + String(Math.floor(Date.now() / 1000) + VERIFIED_RECHECK_COOLDOWN) + '; Path=/; Max-Age=' + VERIFIED_RECHECK_COOLDOWN + '; HttpOnly; Secure; SameSite=Lax');

      ctx.waitUntil(storeBehaviorProfile(env, { event: 'PASSED', fpHash: safeFp, ip, asn, country }));
      ctx.waitUntil(Promise.all([
        sendDiscordWebhookDelayed(env, 'PASSED', 'Challenge Solved', baseDetails, 3000),
        logToD1(env, 'PASSED', 'PoW verified', baseDetails),
        incrementKvStat(env, 'passed'),
        incrementKvStat(env, 'total'),
        clearPowFailStreak(env, ip, safeFp),
      ]));

      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    }

    // ── Skip protection for unprotected routes ──
    if (!runtimePolicy.protectEnabled || !(await shouldProtect(env, url))) {
      return proxyWithMaintenanceFallback(request, 'unprotected_origin_proxy');
    }

    // ── IP Whitelist bypass ──
    if (isWhitelistedIp(ip)) {
      return proxyWithMaintenanceFallback(request, 'whitelist_origin_proxy');
    }

    // ── IP Reputation auto-block ──
    if (ipReputation.autoBlock) {
      const penalty = await escalateIpPenalty(env, ip, 'IP Rep Auto-Block (score: ' + ipReputation.score + ')', baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'HARD_BLOCKED', 'IP Rep Auto-Block', baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlSuspended(host, rayId, 'IP reputation score too high: automated block'), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    // ── IP Blacklist hard block (silent — no webhook, D1 only) ──
    const blacklistStatus = await getIpBlacklistStatus(env, ip);
    if (blacklistStatus.blocked) {
      applyPenaltyToDetails(baseDetails, blacklistStatus.penalty);
      ctx.waitUntil(logToD1(env, 'HARD_BLOCKED', 'IP Blacklisted (' + blacklistStatus.source + ')', baseDetails));
      const reason = blacklistStatus.source.includes('permanent') ? 'Permanently suspended' : 'IP address suspended';
      return new Response(htmlSuspended(host, rayId, reason), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    // ── Bot farm detection (fingerprint reuse across 50+ IPs) ──
    if (isBotFarm) {
      const penalty = await escalateIpPenalty(env, ip, 'Bot farm: fingerprint reused across ' + (behaviorRisk.fpUniqueIps || '50+') + ' IPs', baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'BOT_FARM', 'Bot farm detected: ' + (behaviorRisk.fpUniqueIps || '50+') + ' unique IPs', baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlHardBlock(host, rayId, 'Bot farm detected'), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    // ── AI crawler hard block ──
    if (runtimePolicy.aiCrawlerBlockEnabled && aiCrawler && !isWhitelistedIp(ip)) {
      const penalty = await escalateIpPenalty(env, ip, 'AI crawler blocked', baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'AI_CRAWLER', 'AI crawler blocked: ' + ua.slice(0, 80), baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlAiCrawlerBlocked(host, rayId), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    // ── Country block ──
    if (isCountryBlocked(request, env)) {
      const penalty = await escalateIpPenalty(env, ip, 'Country blocked: ' + country, baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'COUNTRY_BLOCKED', 'Country blocked: ' + country, baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlCountryBlocked(host, rayId, country), {
        status: 403,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
      });
    }

    // ── Hard rate-limit block ──
    if (runtimePolicy.rateLimitEnabled && (hardBlocked || fpHardBlocked)) {
      const penalty = await escalateIpPenalty(env, ip, 'Rate limit exceeded' + (fpHardBlocked ? ' (fingerprint)' : ''), baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      emitBlockLogs(ctx, env, 'RATE_LIMITED', 'Rate limit exceeded', baseDetails, signals, fpHash, ip, asn);
      return new Response(htmlRateLimited(host, rayId), {
        status: 429,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '60' })),
      });
    }

    // ── DDoS anomaly hard block ──
    if (runtimePolicy.ddosBlockEnabled && ddosSuspect && threatScore >= 85) {
      const penalty = await escalateIpPenalty(env, ip, 'DDoS anomaly detected', baseDetails);
      applyPenaltyToDetails(baseDetails, penalty);
      baseDetails._preventedBytes = estimatePreventedBytes(request, signals);
      ctx.waitUntil(Promise.all([
        addPreventedTraffic(env, baseDetails._preventedBytes),
        sendDiscordWebhook(env, 'DDOS_PREVENTED', 'DDoS prevented by Shield', baseDetails),
        sendDiscordWebhook(env, 'HARD_BLOCKED', 'DDoS anomaly detected', baseDetails),
        sendExternalLog(env, 'HARD_BLOCKED', 'DDoS anomaly', baseDetails),
        logToD1(env, 'HARD_BLOCKED', 'DDoS anomaly', baseDetails),
        saveToR2(env, 'HARD_BLOCKED', baseDetails),
        incrementKvStat(env, 'blocked'),
        incrementKvStat(env, 'total'),
        storeBehaviorProfile(env, { event: 'HARD_BLOCKED', fpHash, ip, asn }),
        updateThreatIntel(env, baseDetails, true),
      ]));
      return new Response(htmlDdosBlocked(host, rayId), {
        status: 429,
        headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'retry-after': '120' })),
      });
    }

    // ── Verify existing cookies ──
    // (validated earlier so honeypot checks can safely consider verified sessions)

    // ── Challenge Escalation Decision (reuse pre-computed value) ──
    const escalation = baseDetails._escalation;

    const verifiedHighRisk = verified && (
      headless
      || (runtimePolicy.ddosBlockEnabled && ddosSuspect)
      || (runtimePolicy.rateLimitEnabled && (spam || fpSpam))
      || (runtimePolicy.aiCrawlerBlockEnabled && aiCrawler)
      || (suspicious && threatScore >= 60)
    );
    const needsRiskRecheck = verifiedHighRisk && (!Number.isFinite(recheckUntil) || recheckUntil <= nowSec);

    if (!verified || needsRiskRecheck) {
      if ((method === 'GET' || method === 'HEAD') && !url.pathname.startsWith('/__')) {
        try {
          // Multi-tenant origin probe
          const probeSiteResult = await lookupSite(env, host);
          const probeReq = probeSiteResult.found
            ? buildOriginRequest(new Request(request, { method: 'HEAD' }), probeSiteResult.site)
            : new Request(request, { method: 'HEAD' });
          let probe = await fetch(probeReq);
          if (probe.status === 405) {
            const probeReq2 = probeSiteResult.found
              ? buildOriginRequest(request, probeSiteResult.site)
              : request;
            probe = await fetch(probeReq2);
          }

          if (probe.status >= 500) {
            const alreadyKnown = isOriginKnownDown(host);
            markOriginDown(host);
            const tasks = [logErrorToD1(env, 'Origin responded with ' + probe.status, 'pre_challenge_upstream_5xx', baseDetails)];
            if (!alreadyKnown) {
              tasks.push(sendDiscordWebhook(env, 'ERROR', 'Origin returned ' + probe.status + ' — origin down', baseDetails));
            }
            ctx.waitUntil(Promise.all(tasks));
            return new Response(htmlServiceDown(host, rayId), {
              status: 502,
              headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
            });
          }
        } catch (probeErr) {
          const alreadyKnown = isOriginKnownDown(host);
          markOriginDown(host);
          const tasks = [logErrorToD1(env, 'Origin pre-challenge probe failed: ' + probeErr.message, probeErr.stack, baseDetails)];
          if (!alreadyKnown) {
            tasks.push(sendDiscordWebhook(env, 'ERROR', 'Origin probe failed: ' + probeErr.message, baseDetails));
          }
          ctx.waitUntil(Promise.all(tasks));
          return new Response(htmlServiceDown(host, rayId), {
            status: 502,
            headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
          });
        }
      }

      // Determine specific reason and serve appropriate page
      let eventType = 'CHALLENGED';
      let reason = verified ? 'Risk recheck required' : 'Challenge gate (first visit)';
      let blockPage = null;

      if (isExpired) {
        eventType = 'EXPIRED';
        reason = 'Token expired';
      } else if (headless) {
        eventType = 'BOT_DETECTED';
        reason = 'Headless browser detected';
        if (escalation === 'block') {
          blockPage = htmlBotDetected(host, rayId);
        }
      } else if (ddosSuspect) {
        eventType = 'BLOCKED';
        reason = 'DDoS burst anomaly';
        if (escalation === 'block') {
          blockPage = htmlDdosBlocked(host, rayId);
        }
      } else if (suspicious) {
        eventType = 'BOT_DETECTED';
        reason = 'Bot/scraper detected';
        if (escalation === 'block') {
          blockPage = htmlBotDetected(host, rayId);
        }
      } else if (runtimePolicy.rateLimitEnabled && (spam || fpSpam)) {
        eventType = 'RATE_LIMITED';
        reason = 'Rate limited' + (fpSpam ? ' (fingerprint)' : '');
        if (escalation === 'block') {
          blockPage = htmlRateLimited(host, rayId);
        }
      } else if (runtimePolicy.vpnBlockEnabled && runtimeVpnProxy && !trustedAsnOrg && threatScore >= 50) {
        eventType = 'VPN_BLOCKED';
        reason = 'VPN/Proxy + high threat';
        if (escalation === 'block') {
          blockPage = htmlVpnBlocked(host, rayId);
        }
      }

      const isBlock = escalation === 'block' && blockPage;

      const kvKey = isBlock ? 'blocked'
                  : eventType === 'EXPIRED' ? 'expired'
                  : 'challenged';

      const penalty = isBlock
        ? await escalateIpPenalty(env, ip, reason, baseDetails)
        : null;
      applyPenaltyToDetails(baseDetails, penalty);

      baseDetails._preventedBytes = isBlock ? estimatePreventedBytes(request, signals) : 0;

      ctx.waitUntil(Promise.all([
        baseDetails._preventedBytes ? addPreventedTraffic(env, baseDetails._preventedBytes) : Promise.resolve(),
        sendDiscordWebhook(env, isBlock ? eventType : 'CHALLENGED', reason, baseDetails),
        sendExternalLog(env, isBlock ? eventType : 'CHALLENGED', reason, baseDetails),
        logToD1(env, isBlock ? eventType : 'CHALLENGED', reason, baseDetails),
        saveToR2(env, isBlock ? eventType : 'CHALLENGED', baseDetails),
        incrementKvStat(env, kvKey),
        incrementKvStat(env, 'total'),
        storeBehaviorProfile(env, { event: isBlock ? eventType : 'CHALLENGED', fpHash, ip, asn, country }),
        updateThreatIntel(env, baseDetails, isBlock),
      ]));

      // If escalation says block and we have a specific page, serve it
      if (blockPage) {
        return new Response(blockPage, {
          status: eventType === 'RATE_LIMITED' ? 429 : 403,
          headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })),
        });
      }

      // Otherwise serve the challenge page
      const challengeBody = htmlChallenge(host, rayId, colo, utcTime, threatScore);
      const challengeHeaders = securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }));
      challengeHeaders.append('set-cookie', COOKIE_RISK_NAME + '=' + String(threatScore) + '; Path=/; Max-Age=120; HttpOnly; Secure; SameSite=Lax');
      return new Response(challengeBody, { status: 403, headers: challengeHeaders });
    }

    // ── Passed — proxy to origin ──
    ctx.waitUntil(incrementKvStat(env, 'total'));
    return proxyWithMaintenanceFallback(request, 'passed_origin_proxy');
   } catch (fatalErr) {
    const minDetails = {
      ip: request.headers.get('cf-connecting-ip') || 'N/A',
      country: request.cf?.country || 'N/A',
      host: new URL(request.url).hostname,
      path: new URL(request.url).pathname,
      method: request.method,
      ua: request.headers.get('user-agent') || 'N/A',
      referer: request.headers.get('referer') || 'N/A',
      asOrg: request.cf?.asOrganization || 'N/A',
      asn: String(request.cf?.asn || 'N/A'),
      colo: request.cf?.colo || 'N/A',
      rayId: request.headers.get('cf-ray') || 'N/A',
      tlsVersion: request.cf?.tlsVersion || 'N/A',
      httpVersion: request.cf?.httpProtocol || 'N/A',
      _suspicious: false, _headless: false, _vpn: false, _aiCrawler: false, _spam: false, _attackFlags: [],
    };
    ctx.waitUntil(Promise.all([
      logErrorToD1(env, 'Uncaught: ' + fatalErr.message, fatalErr.stack, minDetails),
      sendDiscordWebhook(env, 'ERROR', 'Uncaught: ' + fatalErr.message, minDetails),
    ]));
    const host = new URL(request.url).hostname;
    const rayId = request.headers.get('cf-ray') || 'N/A';
    return new Response(htmlServiceDown(host, rayId), {
      status: 500,
      headers: securityHeaders(new Headers({ 'content-type': 'text/html; charset=utf-8' })),
    });
   }
  },
};
