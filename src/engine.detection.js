/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Detection Engine
   Bot detection, attack patterns, TLS fingerprinting, threat scoring,
   client classification, challenge escalation
   ═══════════════════════════════════════════════════════════════════ */

import { DDOS_IP_THRESHOLD, DDOS_PREFIX_THRESHOLD } from './core.config.js';
import { normalizeIp } from './core.utils.js';
import { LISTS } from './engine.lists.js';
import { dynamicIpBlacklist } from './engine.blacklist.js';
import { isSpam, isHardBlocked, isFpSpam, isFpHardBlocked, detectTrafficBurst, getHeaderPresenceScore, analyzeRequestPattern } from './engine.traffic.js';

// ─── Bot / Headless / VPN / AI Detection ─────────────────────────
export function isSuspicious(request) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  if (!ua) return true;
  if (ua.length < 30) return true;
  if (LISTS.bot_ua_patterns.some((p) => ua.includes(p))) return true;
  const hasAccept = !!request.headers.get('accept');
  const hasAcceptLang = !!request.headers.get('accept-language');
  const hasAcceptEnc = !!request.headers.get('accept-encoding');
  const hasSec = !!request.headers.get('sec-fetch-mode');
  const missing = [hasAccept, hasAcceptLang, hasAcceptEnc, hasSec].filter(x => !x).length;
  if (missing >= 2) return true;
  return false;
}

export function isHeadless(request) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  if (LISTS.headless_hints.some((p) => ua.includes(p))) return true;
  if (request.headers.get('x-requested-with') === 'puppeteer') return true;
  const secUa = (request.headers.get('sec-ch-ua') || '').toLowerCase();
  if (secUa.includes('headless')) return true;
  return false;
}

export function isVpnProxy(request) {
  const org = (request.cf?.asOrganization || '').toLowerCase();
  if (!org) return false;
  return LISTS.vpn_asn_hints.some((h) => org.includes(h));
}

function isLikelyDatacenterAutomation(request) {
  const org = String(request.cf?.asOrganization || '').toLowerCase();
  if (!org) return false;

  const dcHints = [
    'skyway west', 'digitalocean', 'linode', 'hetzner', 'ovh', 'contabo', 'leaseweb',
    'choopa', 'vultr', 'hivelocity', 'amazon', 'aws', 'google cloud', 'microsoft',
    'azure', 'oracle cloud', 'alibaba cloud', 'tencent cloud', 'data center', 'colo',
  ];
  const isDcAsn = dcHints.some((hint) => org.includes(hint));
  if (!isDcAsn) return false;

  const ua = String(request.headers.get('user-agent') || '').toLowerCase();
  const hasBrowserUa = /\b(mozilla|chrome|safari|firefox|edg|opera)\b/.test(ua);
  const hasSecFetchMode = !!request.headers.get('sec-fetch-mode');
  const hasSecChUa = !!request.headers.get('sec-ch-ua');
  const hasAcceptLang = !!request.headers.get('accept-language');

  if (!hasBrowserUa) return true;
  if (!hasSecFetchMode || !hasSecChUa || !hasAcceptLang) return true;
  return false;
}

export function isAiCrawler(request) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  return LISTS.ai_crawler_patterns.some((p) => ua.includes(p));
}

export function isCountryBlocked(request, env) {
  const blocked = (env?.BLOCKED_COUNTRIES || '').toUpperCase().split(',').map((s) => s.trim()).filter(Boolean);
  if (!blocked.length) return false;
  const country = (request.cf?.country || '').toUpperCase();
  return blocked.includes(country);
}

export function isIpWhitelisted(ip, env) {
  const list = [
    ...(env?.IP_WHITELIST || '').split(','),
    ...(env?.IP_WHITELIST_EXTRA || '').split(','),
  ].map((s) => s.trim()).filter(Boolean);
  return list.includes(ip);
}

// ─── TLS Fingerprinting ─────────────────────────────────────────
export function analyzeTls(request) {
  const tls = request.cf?.tlsVersion || '';
  const cipher = request.cf?.tlsCipher || '';
  const rtt = request.cf?.clientTcpRtt || 0;
  const httpVersion = request.cf?.httpProtocol || '';

  const result = { tlsScore: 0, tlsSignals: [] };

  // Ancient TLS versions
  if (tls === 'TLSv1' || tls === 'TLSv1.1') {
    result.tlsScore += 20;
    result.tlsSignals.push('old_tls');
  } else if (tls === 'TLSv1.2') {
    // TLS 1.2 is fine but slightly less modern
    result.tlsScore += 2;
  }
  // TLS 1.3 is modern and expected — no penalty

  // Suspicious cipher suites (common in bots/scripts)
  if (cipher) {
    const cipherLower = cipher.toLowerCase();
    // Python requests typically uses specific cipher suites
    if (cipherLower.includes('rc4') || cipherLower.includes('des') || cipherLower.includes('null')) {
      result.tlsScore += 15;
      result.tlsSignals.push('weak_cipher');
    }
  }

  // HTTP/1.0 is very suspicious (most bots)
  if (httpVersion === 'HTTP/1.0') {
    result.tlsScore += 12;
    result.tlsSignals.push('http10');
  } else if (httpVersion === 'HTTP/1.1') {
    result.tlsScore += 3; // slightly less modern
  }
  // HTTP/2 and HTTP/3 are expected — no penalty

  // Very low RTT could indicate nearby bot infrastructure
  // Very high RTT is also suspicious (tor/proxy chains)
  if (rtt > 0) {
    if (rtt < 2) {
      result.tlsScore += 5;
      result.tlsSignals.push('ultra_low_rtt');
    } else if (rtt > 2000) {
      result.tlsScore += 5;
      result.tlsSignals.push('very_high_rtt');
    }
  }

  // No TLS at all (plaintext) — extremely suspicious
  if (!tls && httpVersion) {
    result.tlsScore += 25;
    result.tlsSignals.push('no_tls');
  }

  return result;
}

// ─── Attack Pattern Detection ────────────────────────────────────
export function detectAttackPatterns(request) {
  const url = new URL(request.url);
  const fullPath = decodeURIComponent(url.pathname + url.search).toLowerCase();
  const flags = [];

  if (LISTS.path_traversal_patterns.some(p => fullPath.includes(p))) flags.push('PATH_TRAVERSAL');

  const qs = decodeURIComponent(url.search).toLowerCase();
  if (qs && LISTS.sqli_patterns.some(p => qs.includes(p))) flags.push('SQLI');
  if (qs && LISTS.xss_patterns.some(p => qs.includes(p))) flags.push('XSS');

  if (fullPath.includes('%00') || fullPath.includes('\x00')) flags.push('NULL_BYTE');
  if (fullPath.includes('%25')) flags.push('DOUBLE_ENCODE');

  if (url.search.match(/https?%3a|ftp%3a|file%3a|data%3a|javascript%3a/i)) flags.push('PROTOCOL_SMUGGLE');
  if (url.pathname.split('/').length > 15) flags.push('DEEP_PATH');

  const suspiciousExts = ['.bak','.old','.orig','.save','.swp','.tmp','.temp','.log','.sql','.dump','.tar','.gz','.zip','.rar'];
  if (suspiciousExts.some(ext => url.pathname.toLowerCase().endsWith(ext))) flags.push('SUSPICIOUS_EXT');

  // Additional patterns
  if (fullPath.includes('eval(') || fullPath.includes('exec(') || fullPath.includes('system(')) flags.push('CMD_INJECTION');
  if (fullPath.match(/\.(asp|aspx|jsp|cgi|pl)\b/i)) flags.push('LEGACY_SCRIPT');
  if (fullPath.includes('<!--') || fullPath.includes('-->')) flags.push('HTML_COMMENT_INJECT');

  return flags;
}

// ─── Client Classification ──────────────────────────────────────
function isKnownBrowserUa(ua) {
  return /\b(mozilla|chrome|safari|firefox|edg|opera)\b/.test(ua);
}

function hasRobotSignature(ua) {
  return /\b(bot|robot|scraper|harvester|scanner|checker)\b/.test(ua);
}

function hasCrawlerSignature(ua) {
  return /\b(crawl|crawler|spider|indexer)\b/.test(ua);
}

export function classifyClientType(request, signals) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const hasRobotWord = hasRobotSignature(ua);
  const hasCrawlerWord = hasCrawlerSignature(ua);
  const hasBrowserWord = isKnownBrowserUa(ua);

  if (signals.ddosSuspect) return 'ddos';
  if (signals.aiCrawler) return 'ai-crawler';
  if (signals.headless) return 'automation-bot';
  if (signals.suspicious && hasRobotWord) return 'robot';
  if (signals.suspicious && hasCrawlerWord) return 'crawler';
  if (signals.suspicious) return 'bot';
  if (hasBrowserWord && signals.headerPresenceScore >= 5) return 'user';
  if (hasCrawlerWord) return 'crawler';
  return 'unknown';
}

// ─── Build Detection Signals ─────────────────────────────────────
export function buildDetectionSignals(request, ip, nowMs, behaviorRisk = {}) {
  const url = new URL(request.url);
  const headerPresenceScore = getHeaderPresenceScore(request);
  const datacenterAutomation = isLikelyDatacenterAutomation(request);
  const suspicious = isSuspicious(request) || datacenterAutomation;
  const headless = isHeadless(request);
  const vpn = isVpnProxy(request) || datacenterAutomation;
  const aiCrawler = isAiCrawler(request);
  const spam = isSpam(ip, nowMs);
  const hardBlocked = isHardBlocked(ip, nowMs);
  const attackFlags = detectAttackPatterns(request);
  const trafficBurst = detectTrafficBurst(ip, nowMs);
  const tlsAnalysis = analyzeTls(request);
  const fpHash = behaviorRisk._fpHash || '';
  const fpSpam = isFpSpam(fpHash, nowMs);
  const fpHardBlocked = isFpHardBlocked(fpHash, nowMs);
  const requestPattern = analyzeRequestPattern(ip, url.pathname, url.search, nowMs);

  const ddosSuspect =
    trafficBurst.ddosSuspect ||
    (spam && headerPresenceScore <= 2) ||
    (attackFlags.length >= 2 && trafficBurst.prefixBurst);

  const clientType = classifyClientType(request, {
    suspicious, headless, aiCrawler, ddosSuspect, headerPresenceScore,
  });

  return {
    suspicious, headless, vpn, aiCrawler, spam, hardBlocked,
    attackFlags, headerPresenceScore, ddosSuspect, clientType,
    ipRate: trafficBurst.ipRate,
    prefixRate: trafficBurst.prefixRate,
    ipPrefix: trafficBurst.ipPrefix,
    fpRisk: Number(behaviorRisk.fpRisk || 0),
    asnRisk: Number(behaviorRisk.asnRisk || 0),
    countryRisk: Number(behaviorRisk.countryRisk || 0),
    bypassAttempts: Number(behaviorRisk.bypassAttempts || 0),
    isBotFarm: !!behaviorRisk.isBotFarm,
    countryAnomaly: !!behaviorRisk.countryAnomaly,
    tlsScore: tlsAnalysis.tlsScore,
    tlsSignals: tlsAnalysis.tlsSignals,
    fpSpam,
    fpHardBlocked,
    patternScore: requestPattern.patternScore,
    identicalPathBurst: requestPattern.identicalPathBurst,
    paramEnumeration: requestPattern.paramEnumeration,
  };
}

// ─── Weighted AI-Like Threat Scoring ─────────────────────────────
export function computeThreatScore(request, signals) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();

  // Weighted category scores
  let uaScore = 0;        // User-Agent analysis (max ~50)
  let behaviorScore = 0;  // Bot behavior signals (max ~60)
  let networkScore = 0;   // Network/TLS signals (max ~40)
  let reputationScore = 0; // IP/FP/ASN reputation (max ~50)
  let attackScore = 0;    // Attack patterns (max ~50)
  let patternScore = 0;   // Request patterns (max ~30)

  const {
    spam = false, vpn = false, suspicious = false, headless = false,
    aiCrawler = false, attackFlags = [], ddosSuspect = false,
    headerPresenceScore = 0, clientType = 'unknown',
    ipRate = 0, prefixRate = 0,
    fpRisk = 0, asnRisk = 0, countryRisk = 0, bypassAttempts = 0,
    isBotFarm = false, countryAnomaly = false,
    tlsScore = 0, tlsSignals = [],
    fpSpam = false, fpHardBlocked = false,
    identicalPathBurst = false, paramEnumeration = false,
  } = signals || {};

  // ── UA Score ──
  if (!ua || ua.length < 20) uaScore += 15;
  else if (ua.length < 40) uaScore += 8;
  if (ua.length > 500) uaScore += 10;
  if (ua && !ua.includes('mozilla') && !ua.includes('chrome') && !ua.includes('safari') && !ua.includes('firefox') && !ua.includes('edge') && !ua.includes('opera')) uaScore += 15;

  // ── Behavior Score ──
  if (suspicious) behaviorScore += 30;
  if (headless) behaviorScore += 35;
  if (spam) behaviorScore += 25;
  if (aiCrawler) behaviorScore += 20;
  if (ddosSuspect) behaviorScore += 35;
  if (fpSpam) behaviorScore += 15;
  if (fpHardBlocked) behaviorScore += 20;
  if (!request.headers.get('accept-language')) behaviorScore += 6;
  if (!request.headers.get('accept')) behaviorScore += 6;
  if (!request.headers.get('accept-encoding')) behaviorScore += 4;
  if (!request.headers.get('sec-fetch-mode')) behaviorScore += 6;
  if (!request.headers.get('sec-fetch-site')) behaviorScore += 4;
  if (!request.headers.get('sec-fetch-dest')) behaviorScore += 4;
  if (headerPresenceScore <= 2) behaviorScore += 10;
  if (clientType === 'ddos') behaviorScore += 20;
  if (clientType === 'robot' || clientType === 'bot' || clientType === 'automation-bot') behaviorScore += 8;
  if (clientType === 'crawler') behaviorScore += 6;
  const method = request.method;
  if (['TRACE', 'TRACK', 'DEBUG', 'CONNECT'].includes(method)) behaviorScore += 20;
  if (method === 'OPTIONS' || method === 'DELETE' || method === 'PATCH') behaviorScore += 4;

  // ── Network Score ──
  if (vpn) networkScore += 18;
  if (ipRate >= DDOS_IP_THRESHOLD) networkScore += 12;
  if (prefixRate >= DDOS_PREFIX_THRESHOLD) networkScore += 12;
  networkScore += Math.min(20, tlsScore);
  if (request.cf?.botManagement?.score !== undefined) {
    const botScore = request.cf.botManagement.score;
    if (botScore < 20) networkScore += 25;
    else if (botScore < 40) networkScore += 15;
    else if (botScore < 60) networkScore += 8;
  }
  if (request.cf?.threatScore !== undefined) {
    const cfThreat = request.cf.threatScore;
    if (cfThreat > 50) networkScore += 15;
    else if (cfThreat > 20) networkScore += 8;
    else if (cfThreat > 10) networkScore += 4;
  }

  // ── Reputation Score ──
  reputationScore += Math.min(30, fpRisk);
  reputationScore += Math.min(18, asnRisk);
  reputationScore += Math.min(12, countryRisk);
  if (bypassAttempts > 0) reputationScore += Math.min(15, bypassAttempts * 3);
  if (isBotFarm) reputationScore += 30;
  if (countryAnomaly) reputationScore += 10;

  // ── Attack Score ──
  if (attackFlags.includes('SQLI')) attackScore += 40;
  if (attackFlags.includes('XSS')) attackScore += 35;
  if (attackFlags.includes('PATH_TRAVERSAL')) attackScore += 30;
  if (attackFlags.includes('CMD_INJECTION')) attackScore += 40;
  if (attackFlags.includes('NULL_BYTE')) attackScore += 25;
  if (attackFlags.includes('DOUBLE_ENCODE')) attackScore += 15;
  if (attackFlags.includes('PROTOCOL_SMUGGLE')) attackScore += 20;
  if (attackFlags.includes('DEEP_PATH')) attackScore += 10;
  if (attackFlags.includes('SUSPICIOUS_EXT')) attackScore += 10;
  if (attackFlags.includes('LEGACY_SCRIPT')) attackScore += 8;
  if (attackFlags.includes('HTML_COMMENT_INJECT')) attackScore += 10;

  // ── Pattern Score ──
  patternScore += (signals.patternScore || 0);
  if (identicalPathBurst) patternScore += 5;
  if (paramEnumeration) patternScore += 5;

  // ── Weighted combination ──
  // Prioritize behavior + fingerprint/reputation dominance
  // Weights: behavior(0.38) + reputation(0.24) + network(0.15) + ua(0.10) + attack(0.08) + pattern(0.05)
  const weighted =
    Math.min(60, behaviorScore) * 0.38 +
    Math.min(50, reputationScore) * 0.24 +
    Math.min(40, networkScore) * 0.15 +
    Math.min(50, uaScore) * 0.10 +
    Math.min(50, attackScore) * 0.08 +
    Math.min(30, patternScore) * 0.05;

  // Normalize to 0-100 and add raw bonuses for critical signals
  let finalScore = Math.round(weighted * 2.2);

  // Critical signal bonuses (can push score very high)
  if (isBotFarm) finalScore += 15;
  if (attackFlags.length >= 2) finalScore += 10;
  if (ddosSuspect && headless) finalScore += 10;

  return Math.min(finalScore, 100);
}

// ─── Challenge Escalation ────────────────────────────────────────
// Determines what action to take based on threat score
export function determineEscalation(threatScore, signals) {
  // very high → hard block
  if (threatScore >= 85) return 'block';
  if (signals.isBotFarm) return 'block';
  if (signals.fpHardBlocked) return 'block';

  // high → PoW challenge (hard difficulty)
  if (threatScore >= 60) return 'pow-hard';

  // medium → standard PoW challenge
  if (threatScore >= 30) return 'pow';

  // low-medium → lightweight JS challenge
  if (threatScore >= 15) return 'pow-lite';

  // low → allow through
  return 'allow';
}

// ─── Route Protection (dynamic — checks D1 protected_sites + env fallback) ──
export async function shouldProtect(env, url) {
  const host = url.hostname.toLowerCase();

  // 0) Explicit unprotected host/domain bypass (comma-separated)
  const unprotectedDomains = (env?.UNPROTECTED_DOMAINS || '')
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  for (const d of unprotectedDomains) {
    if (host === d || host.endsWith('.' + d)) return false;
  }

  // 1) Check env-configured protected domains (comma-separated)
  const envDomains = (env?.PROTECTED_DOMAINS || '').split(',').map(d => d.trim().toLowerCase()).filter(Boolean);
  for (const d of envDomains) {
    if (host === d || host.endsWith('.' + d)) return true;
  }

  // 2) Check D1 protected_sites table
  if (env?.SHIELD_DB) {
    try {
      // Try exact match first, then wildcard parent
      const row = await env.SHIELD_DB.prepare(
        'SELECT 1 FROM protected_sites WHERE (domain = ? OR domain = ?) AND active = 1 LIMIT 1'
      ).bind(host, host.replace(/^[^.]+\./, '')).first();
      if (row) return true;
    } catch { /* DB error — fall through */ }
  }

  // 3) Default: if request reached this Worker route, protect it.
  return true;
}
