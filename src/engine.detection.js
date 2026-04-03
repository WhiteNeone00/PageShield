/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Detection Engine
   Bot detection, attack patterns, TLS fingerprinting, threat scoring,
   client classification, challenge escalation
   ═══════════════════════════════════════════════════════════════════ */

import { DDOS_IP_THRESHOLD, DDOS_PREFIX_THRESHOLD, DDOS_ASN_THRESHOLD } from './core.config.js';
import { normalizeIp } from './core.utils.js';
import { LISTS } from './engine.lists.js';
import { dynamicIpBlacklist } from './engine.blacklist.js';
import { isSpam, isHardBlocked, isFpSpam, isFpHardBlocked, detectTrafficBurst, getHeaderPresenceScore, analyzeRequestPattern } from './engine.traffic.js';

const AI_CRAWLER_FALLBACK = [
  'gptbot', 'chatgpt-user', 'chatgpt-image', 'oai-searchbot', 'openai-search',
  'claudebot', 'anthropic-ai', 'perplexitybot', 'cohere-ai', 'cohere-training-data-crawler',
  'bytespider', 'bytspider', 'ccbot', 'diffbot', 'imagesiftbot', 'duckassistbot',
  'google-extended', 'googleother', 'googleother-image', 'googleother-video',
  'applebot-extended', 'meta-externalagent', 'facebookbot', 'amazonbot',
  'omgilibot', 'petalbot', 'youbot', 'seekr', 'exa', 'you.com', 'phindbot',
  'timpibot', 'andibot',
];

const DATACENTER_ORG_HINTS = [
  'amazon', 'aws', 'google cloud', 'google llc', 'microsoft', 'azure', 'oracle',
  'oracle cloud', 'alibaba cloud', 'tencent cloud', 'ibm cloud', 'cloudflare', 'edge',
  'akamai', 'fastly', 'edgecast', 'cdn77', 'stackpath', 'bunny', 'leaseweb', 'ovh',
  'hetzner', 'contabo', 'digitalocean', 'linode', 'akamai connected cloud', 'choopa',
  'vultr', 'hivelocity', 'kamatera', 'm247', 'psychz', 'colo', 'data center',
  'hostwinds', 'netcup', 'ionos', 'online sas', 'scaleway', 'racknerd', 'quadranet',
  'zenlayer', 'colocrossing', 'gcore', 'mevspace', 'servermania', 'nocix',
];

const SCANNER_UA_REGEX = /\b(sqlmap|nmap|masscan|zgrab|nikto|nessus|openvas|acunetix|nuclei|dirbuster|gobuster|ffuf|feroxbuster|wpscan|whatweb|metasploit|amass|naabu|httpx|jaeles|wapiti|arachni|gospider|dirsearch)\b/;
const SCANNER_PATH_REGEX = /\/(?:\.env|\.git|phpmyadmin|wp-admin|wp-login\.php|xmlrpc\.php|vendor\/phpunit|cgi-bin|server-status|actuator|hudson|jenkins|boaform\/admin\/formlogin|manager\/html|autodiscover\/autodiscover\.xml|adminer\.php|solr\/admin|\.vscode|\.idea|\.svn|\.hg|owa\/auth\/logon\.aspx|_ignition\/execute-solution|HNAP1)\b/i;
const INJECTION_PATTERN_REGEX = /(\$\{jndi:|union(?:\+|\s)select|<script|%3cscript|\.\.\/|%2e%2e%2f|php:\/\/|file:\/\/|proc\/self\/environ|cmd=|exec=|powershell|base64_)/i;
const SSRF_PATTERN_REGEX = /(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal|\.[a-z0-9-]+\.internal|\.svc(?:\.cluster\.local)?|\[::1\])/i;
const GRAPHQL_INTROSPECTION_REGEX = /(?:__schema|__type)\s*(?:\{|\()/i;
const HEADER_INJECTION_REGEX = /(%0d%0a|\r\n)/i;
const TEMPLATE_INJECTION_REGEX = /(\{\{[^}]{1,80}\}\}|\$\{[^}]{1,80}\}|<%=?[^%]{1,120}%>|\b(?:__globals__|__mro__|__subclasses__)\b)/i;
const SHELL_PAYLOAD_REGEX = /((?:;|\|\||&&)\s*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|powershell|cmd\.exe)\b|\$\([^)]{1,120}\)|`[^`]{1,120}`)/i;
const METHOD_OVERRIDE_HEADERS = ['x-http-method-override', 'x-method-override', 'x-http-method'];
const LEARN_TTL_MS = 6 * 60 * 60 * 1000;
const LEARN_MIN_HITS = 2;
const UA_STOP_TOKENS = new Set([
  'mozilla', 'applewebkit', 'chrome', 'safari', 'firefox', 'edg', 'gecko',
  'khtml', 'like', 'version', 'mobile', 'linux', 'windows', 'android',
  'iphone', 'ipad', 'macintosh', 'x64', 'x86_64', 'compatible', 'wow64',
]);

const LEARNED = {
  aiUa: new Map(),
  botUa: new Map(),
  scannerUa: new Map(),
  vpnOrg: new Map(),
  dcOrg: new Map(),
};

function safeDecode(input) {
  const value = String(input || '');
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function shannonEntropy(value) {
  const text = String(value || '');
  if (!text) return 0;
  const counts = new Map();
  for (const char of text) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function hasJwtNoneAlgorithm(request) {
  const auth = String(request.headers.get('authorization') || '');
  if (!auth.toLowerCase().startsWith('bearer ')) return false;
  const token = auth.slice(7).trim();
  if (!token || token.split('.').length < 2) return false;
  const [headerPart] = token.split('.', 1);
  const normalized = headerPart.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  try {
    const decoded = atob(normalized + '='.repeat(padLen)).toLowerCase();
    return decoded.includes('"alg":"none"') || decoded.includes('"alg": "none"');
  } catch {
    return false;
  }
}

function getDetectionConfig(policy = {}) {
  if (!policy || typeof policy !== 'object') return {};
  return policy.detection && typeof policy.detection === 'object' ? policy.detection : {};
}

function normalizeList(value) {
  const list = Array.isArray(value) ? value : [];
  return list.map((v) => String(v || '').trim().toLowerCase()).filter(Boolean);
}

function mergeHints(base, extra) {
  return [...new Set([...normalizeList(base), ...normalizeList(extra)])];
}

function pruneExpired(map, nowMs) {
  for (const [token, entry] of map.entries()) {
    if (!entry || Number(entry.expiresAt || 0) <= nowMs) map.delete(token);
  }
}

function bumpLearned(map, token, nowMs, weight = 1) {
  if (!token) return;
  const prev = map.get(token) || { hits: 0, score: 0, expiresAt: nowMs + LEARN_TTL_MS };
  map.set(token, {
    hits: Number(prev.hits || 0) + 1,
    score: Number(prev.score || 0) + Math.max(1, Number(weight || 1)),
    expiresAt: nowMs + LEARN_TTL_MS,
  });
}

function hasLearnedMatch(map, text, nowMs, minHits = LEARN_MIN_HITS, minScore = 3) {
  if (!text) return false;
  pruneExpired(map, nowMs);
  for (const [token, entry] of map.entries()) {
    if (!token || !entry) continue;
    if (Number(entry.hits || 0) < minHits) continue;
    if (Number(entry.score || 0) < minScore) continue;
    if (text.includes(token)) return true;
  }
  return false;
}

function extractUaTokens(ua) {
  if (!ua) return [];
  return ua
    .split(/[^a-z0-9._-]+/g)
    .map((t) => t.trim())
    .filter((t) => t.length >= 4 && t.length <= 40 && !UA_STOP_TOKENS.has(t));
}

function extractOrgTokens(org) {
  if (!org) return [];
  return org
    .split(/[^a-z0-9]+/g)
    .map((t) => t.trim())
    .filter((t) => t.length >= 4 && t.length <= 28 && t !== 'cloud' && t !== 'group');
}

function hasForwardProxyHeaders(request) {
  const forwarded = String(request.headers.get('forwarded') || '').toLowerCase();
  const via = String(request.headers.get('via') || '').toLowerCase();
  const xff = String(request.headers.get('x-forwarded-for') || '').toLowerCase();

  // In a CF Worker context, Cloudflare itself adds x-forwarded-for (single IP),
  // true-client-ip, and forwarded headers. Only flag genuine multi-hop proxy chains.

  // Multiple "for=" entries in Forwarded header → real proxy chain
  if (forwarded && (forwarded.match(/for=/g) || []).length >= 2) return true;

  // Via header from a non-Cloudflare proxy
  if (via && !via.includes('cloudflare') && !via.includes('1.1 vegur')) return true;

  // XFF with 3+ IPs indicates client → proxy → proxy → Cloudflare
  if (xff) {
    const ips = xff.split(',').map(s => s.trim()).filter(Boolean);
    if (ips.length >= 3) return true;
  }

  return false;
}

function getHeaderCount(headers) {
  let count = 0;
  for (const _ of headers) count += 1;
  return count;
}

function hasMethodOverrideAbuse(request) {
  const actualMethod = String(request.method || 'GET').toUpperCase();
  const dangerousOverrides = new Set(['TRACE', 'TRACK', 'CONNECT', 'DELETE', 'PUT', 'PATCH']);

  for (const headerName of METHOD_OVERRIDE_HEADERS) {
    const raw = String(request.headers.get(headerName) || '').trim();
    if (!raw) continue;
    const overrideMethod = raw.split(',')[0].trim().toUpperCase();
    if (!overrideMethod) continue;
    if (dangerousOverrides.has(overrideMethod)) return true;
    if ((actualMethod === 'GET' || actualMethod === 'HEAD') && overrideMethod !== actualMethod) return true;
  }

  return false;
}

function rememberEmergingSignatures(request, signals, nowMs) {
  const ua = String(request.headers.get('user-agent') || '').toLowerCase();
  const org = String(request.cf?.asOrganization || '').toLowerCase();
  const attackFlags = Array.isArray(signals.attackFlags) ? signals.attackFlags : [];

  const uaTokens = extractUaTokens(ua);
  const orgTokens = extractOrgTokens(org);

  if (signals.aiCrawler || Number(signals.aiSignalScore || 0) >= 45) {
    for (const token of uaTokens) bumpLearned(LEARNED.aiUa, token, nowMs, 2);
  }

  if (signals.headless || signals.ddosSuspect || Number(signals.botSignalScore || 0) >= 35 || signals.suspicious) {
    for (const token of uaTokens) bumpLearned(LEARNED.botUa, token, nowMs, 1);
  }

  if (
    Number(signals.scannerSignalScore || 0) >= 35
    || attackFlags.includes('SCANNER_UA')
    || attackFlags.includes('SCANNER_PATH')
    || attackFlags.includes('INJECTION_PROBE')
    || attackFlags.includes('RECON_SCAN')
    || attackFlags.includes('SSRF_PROBE')
    || attackFlags.includes('GRAPHQL_INTROSPECTION')
    || attackFlags.includes('HEADER_INJECTION')
    || attackFlags.includes('JWT_NONE_ALG')
    || attackFlags.includes('TEMPLATE_INJECTION')
    || attackFlags.includes('SHELL_PAYLOAD')
    || attackFlags.includes('METHOD_OVERRIDE_ABUSE')
    || attackFlags.includes('COOKIE_ABUSE')
    || attackFlags.includes('HEADER_FLOOD')
  ) {
    for (const token of uaTokens) bumpLearned(LEARNED.scannerUa, token, nowMs, 2);
  }

  if (signals.vpn) {
    for (const token of orgTokens) bumpLearned(LEARNED.vpnOrg, token, nowMs, 2);
  }

  if (signals.datacenterAutomation || signals.vpn || signals.ddosSuspect) {
    for (const token of orgTokens) bumpLearned(LEARNED.dcOrg, token, nowMs, 1);
  }
}

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

function automationUaFallback(ua) {
  const hints = [
    'curl/', 'wget/', 'python-requests', 'python-httpx', 'aiohttp', 'go-http-client',
    'okhttp', 'java/', 'libwww-perl', 'httpclient', 'axios/', 'node-fetch', 'python-urllib',
    'scrapy', 'mechanize', 'restsharp', 'resty',
    'headlesschrome', 'phantomjs', 'selenium', 'playwright', 'puppeteer',
    'zgrab', 'masscan', 'nmap', 'sqlmap', 'nikto', 'nessus', 'openvas',
    'acunetix', 'nuclei', 'dirbuster', 'gobuster', 'ffuf', 'feroxbuster',
    'wpscan', 'whatweb', 'httpx', 'jaeles', 'metasploit', 'naabu', 'amass', 'dirsearch',
  ];
  return hints.some((hint) => ua.includes(hint));
}

export function isHeadless(request) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  if (LISTS.headless_hints.some((p) => ua.includes(p))) return true;
  if (request.headers.get('x-requested-with') === 'puppeteer') return true;
  const secUa = (request.headers.get('sec-ch-ua') || '').toLowerCase();
  if (secUa.includes('headless')) return true;
  return false;
}

export function isVpnProxy(request, nowMs = Date.now(), extraHints = []) {
  const org = (request.cf?.asOrganization || '').toLowerCase();
  const city = (request.cf?.city || '').toLowerCase();
  if (!org && !city) return hasForwardProxyHeaders(request);

  const vpnHints = mergeHints(LISTS.vpn_asn_hints || [], extraHints);
  if (vpnHints.some((h) => org.includes(h))) return true;
  if (hasLearnedMatch(LEARNED.vpnOrg, org, nowMs, 2, 3)) return true;
  if (hasLearnedMatch(LEARNED.dcOrg, org, nowMs, 3, 4) && hasForwardProxyHeaders(request)) return true;
  // Only flag as VPN/proxy if ASN actually matches known patterns — don't catch-all
  return false;
}

function isLikelyDatacenterAutomation(request, nowMs = Date.now()) {
  const org = String(request.cf?.asOrganization || '').toLowerCase();
  if (!org) return false;

  const isDcAsn = DATACENTER_ORG_HINTS.some((hint) => org.includes(hint)) || hasLearnedMatch(LEARNED.dcOrg, org, nowMs, 2, 3);
  if (!isDcAsn) return false;

  const ua = String(request.headers.get('user-agent') || '').toLowerCase();
  const method = String(request.method || 'GET').toUpperCase();
  const hasBrowserUa = /\b(mozilla|chrome|safari|firefox|edg|opera)\b/.test(ua);
  const hasSecFetchMode = !!request.headers.get('sec-fetch-mode');
  const hasSecChUa = !!request.headers.get('sec-ch-ua');
  const hasAcceptLang = !!request.headers.get('accept-language');

  if (automationUaFallback(ua)) return true;
  if (!hasBrowserUa) return true;
  if (['TRACE', 'TRACK', 'DEBUG', 'CONNECT'].includes(method)) return true;
  if (!hasSecFetchMode || !hasSecChUa || !hasAcceptLang) return true;
  return false;
}

export function isAiCrawler(request, nowMs = Date.now(), customPatterns = []) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const aiPatterns = mergeHints(LISTS.ai_crawler_patterns || [], customPatterns);
  if (aiPatterns.some((p) => ua.includes(p))) return true;
  if (hasLearnedMatch(LEARNED.aiUa, ua, nowMs, 2, 4)) return true;
  return AI_CRAWLER_FALLBACK.some((p) => ua.includes(p));
}

function evaluateScannerHeuristics(request, detection = {}) {
  const ua = String(request.headers.get('user-agent') || '').toLowerCase();
  const url = new URL(request.url);
  const rawPath = url.pathname + url.search;
  const fullPath = safeDecode(rawPath).toLowerCase();
  const decodedQuery = safeDecode(url.search).toLowerCase();
  const mergedPayload = `${fullPath} ${decodedQuery}`;
  const customScannerPatterns = normalizeList(detection.customScannerUaPatterns || []);
  const customAttackPathPatterns = normalizeList(detection.customAttackPathPatterns || []);
  const enableSsrfDetection = detection.enableSsrfDetection !== false;
  const enableGraphqlIntrospectionDetection = detection.enableGraphqlIntrospectionDetection !== false;
  const enableHeaderInjectionDetection = detection.enableHeaderInjectionDetection !== false;
  const enableTemplateInjectionDetection = detection.enableTemplateInjectionDetection !== false;
  const enableShellPayloadDetection = detection.enableShellPayloadDetection !== false;
  const enableMethodOverrideDetection = detection.enableMethodOverrideDetection !== false;
  const hasScannerUa = SCANNER_UA_REGEX.test(ua) || customScannerPatterns.some((p) => ua.includes(p));
  const scannerPath = SCANNER_PATH_REGEX.test(fullPath);
  const injectionLike = INJECTION_PATTERN_REGEX.test(fullPath) || customAttackPathPatterns.some((p) => fullPath.includes(p));
  const ssrfProbe = enableSsrfDetection
    && /(?:^|[?&](?:url|uri|target|dest|redirect|next|callback|endpoint|proxy)=)/i.test(decodedQuery)
    && SSRF_PATTERN_REGEX.test(decodedQuery);
  const graphqlIntrospection = enableGraphqlIntrospectionDetection
    && (url.pathname.toLowerCase().includes('/graphql') || decodedQuery.includes('graphql'))
    && GRAPHQL_INTROSPECTION_REGEX.test(decodedQuery);
  const headerInjection = enableHeaderInjectionDetection && HEADER_INJECTION_REGEX.test(rawPath);
  const templateInjection = enableTemplateInjectionDetection && TEMPLATE_INJECTION_REGEX.test(mergedPayload);
  const shellPayload = enableShellPayloadDetection && SHELL_PAYLOAD_REGEX.test(mergedPayload);
  const methodOverrideAbuse = enableMethodOverrideDetection && hasMethodOverrideAbuse(request);
  const encodedTokenCount = (rawPath.match(/%[0-9a-f]{2}/gi) || []).length;
  const queryCount = Array.from(url.searchParams.keys()).length;

  let score = 0;
  if (hasScannerUa) score += 45;
  if (scannerPath) score += 30;
  if (injectionLike) score += 25;
  if (ssrfProbe) score += 24;
  if (graphqlIntrospection) score += 20;
  if (headerInjection) score += 22;
  if (templateInjection) score += 28;
  if (shellPayload) score += 32;
  if (methodOverrideAbuse) score += 14;
  if (encodedTokenCount >= 14) score += 8;
  if (queryCount >= 18) score += 12;

  return {
    scannerHeuristicScore: score,
    hasScannerUa,
    scannerPath,
    injectionLike,
    ssrfProbe,
    graphqlIntrospection,
    headerInjection,
    templateInjection,
    shellPayload,
    methodOverrideAbuse,
  };
}

function evaluateAutomationSignals(request, headerPresenceScore, detection = {}) {
  const ua = String(request.headers.get('user-agent') || '').toLowerCase();
  const nowMs = Date.now();
  const customScannerPatterns = normalizeList(detection.customScannerUaPatterns || []);
  const customAiPatterns = normalizeList(detection.customAiCrawlerPatterns || []);
  let botSignalScore = 0;
  let aiSignalScore = 0;
  let scannerSignalScore = 0;

  const hasBrowserUa = /\b(mozilla|chrome|safari|firefox|edg|opera)\b/.test(ua);
  const hasSecFetchMode = !!request.headers.get('sec-fetch-mode');
  const hasSecFetchSite = !!request.headers.get('sec-fetch-site');
  const hasSecChUa = !!request.headers.get('sec-ch-ua');
  const hasAcceptLang = !!request.headers.get('accept-language');
  const hasReferer = !!request.headers.get('referer');
  const hasUpgradeInsecure = !!request.headers.get('upgrade-insecure-requests');
  const path = new URL(request.url).pathname.toLowerCase();

  if (automationUaFallback(ua)) botSignalScore += 35;
  if (hasLearnedMatch(LEARNED.botUa, ua, nowMs, 2, 4)) botSignalScore += 22;
  if (!hasBrowserUa) botSignalScore += 10;
  if (!hasSecFetchMode) botSignalScore += 8;
  if (!hasSecFetchSite) botSignalScore += 4;
  if (!hasSecChUa) botSignalScore += 8;
  if (!hasAcceptLang) botSignalScore += 6;
  if (!hasReferer) botSignalScore += 3;
  if (hasBrowserUa && !hasUpgradeInsecure) botSignalScore += 3;
  if (headerPresenceScore <= 2) botSignalScore += 10;
  if (headerPresenceScore <= 1) botSignalScore += 8;

  const scannerWord = SCANNER_UA_REGEX.test(ua) || customScannerPatterns.some((p) => ua.includes(p));
  if (scannerWord) scannerSignalScore += 45;
  if (hasLearnedMatch(LEARNED.scannerUa, ua, nowMs, 2, 4)) scannerSignalScore += 25;
  if (SCANNER_PATH_REGEX.test(path)) scannerSignalScore += 20;

  const crawlerWord = /\b(bot|crawler|spider|scraper|indexer)\b/.test(ua);
  if (crawlerWord) aiSignalScore += 20;
  if (/\b(gptbot|claudebot|perplexitybot|bytespider|cohere-ai|ccbot|oai-searchbot|meta-externalagent|google-extended)\b/.test(ua)) aiSignalScore += 45;
  if (customAiPatterns.some((p) => ua.includes(p))) aiSignalScore += 30;
  if ((path === '/robots.txt' || path === '/sitemap.xml') && crawlerWord) aiSignalScore += 15;

  if (/\b(wp-admin|phpmyadmin|\.env|\.git|actuator|hudson|jenkins|server-status|xmlrpc\.php|cgi-bin|adminer\.php)\b/.test(path)) scannerSignalScore += 20;

  return { botSignalScore, aiSignalScore, scannerSignalScore };
}

function evaluateRequestAnomalies(request, detection = {}) {
  const ua = String(request.headers.get('user-agent') || '').toLowerCase();
  const method = String(request.method || 'GET').toUpperCase();
  const accept = String(request.headers.get('accept') || '').toLowerCase();
  const contentType = String(request.headers.get('content-type') || '').toLowerCase();
  const contentLength = Number(request.headers.get('content-length') || 0);
  const transferEncoding = String(request.headers.get('transfer-encoding') || '').toLowerCase();
  const secFetchMode = String(request.headers.get('sec-fetch-mode') || '').toLowerCase();
  const secFetchSite = String(request.headers.get('sec-fetch-site') || '').toLowerCase();
  const secChUa = String(request.headers.get('sec-ch-ua') || '').toLowerCase();
  const acceptLanguage = String(request.headers.get('accept-language') || '').toLowerCase();
  const hasReferer = !!request.headers.get('referer');
  const xForwardedFor = String(request.headers.get('x-forwarded-for') || '').toLowerCase();
  const cookieHeader = String(request.headers.get('cookie') || '');
  const headerCount = getHeaderCount(request.headers);
  const url = new URL(request.url);
  const path = url.pathname.toLowerCase();
  const queryRaw = url.search.startsWith('?') ? url.search.slice(1) : url.search;

  let anomalyScore = 0;
  let spoofScore = 0;
  let authTargetingScore = 0;
  let queryEntropyScore = 0;
  let requestSmugglingSignal = false;
  let suspiciousCookieSignal = false;
  let headerFloodSignal = false;

  const looksBrowserUa = /\b(mozilla|chrome|safari|firefox|edg|opera)\b/.test(ua);
  const looksChromeLike = /\b(chrome|edg)\b/.test(ua);

  if (method === 'GET' && contentType) anomalyScore += 6;
  if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && contentLength > 0 && !contentType) anomalyScore += 10;
  if (method === 'HEAD' && contentLength > 0) anomalyScore += 8;

  // accept: */* is normal for fetch/XHR — only penalise on navigations (GET without sec-fetch-dest: document)
  const secFetchDest = String(request.headers.get('sec-fetch-dest') || '').toLowerCase();
  if (looksBrowserUa && accept === '*/*' && method === 'GET' && secFetchDest === 'document') spoofScore += 6;
  if (looksBrowserUa && !secFetchMode) spoofScore += 7;
  if (looksBrowserUa && !secFetchSite) spoofScore += 5;
  if (looksChromeLike && !secChUa) spoofScore += 9;
  if (looksBrowserUa && !acceptLanguage) spoofScore += 7;
  if (!looksBrowserUa && (secFetchMode || secFetchSite || secChUa)) spoofScore += 6;
  // Only penalise multi-hop proxy chains (3+ IPs), not Cloudflare single-hop
  if (xForwardedFor) {
    const xffCount = xForwardedFor.split(',').filter(s => s.trim()).length;
    if (xffCount >= 3) spoofScore += 5;
  }
  if (hasForwardProxyHeaders(request)) spoofScore += 4;

  const hasContentLength = request.headers.has('content-length');
  const hasTransferEncoding = !!transferEncoding;
  if (detection.enableRequestSmugglingDetection !== false) {
    if (hasContentLength && hasTransferEncoding) {
      anomalyScore += 18;
      requestSmugglingSignal = true;
    }
    if (hasTransferEncoding && !transferEncoding.includes('chunked')) {
      anomalyScore += 12;
      requestSmugglingSignal = true;
    }
  }

  const crawlerTargetPath = path === '/robots.txt' || path === '/sitemap.xml' || path.startsWith('/wp-json');
  if (crawlerTargetPath && !looksBrowserUa) anomalyScore += 10;
  if (Array.from(url.searchParams.keys()).length >= 20) anomalyScore += 12;
  if (INJECTION_PATTERN_REGEX.test(safeDecode(url.pathname + url.search))) anomalyScore += 15;

  if (detection.enableEntropyDetection !== false) {
    const entropy = shannonEntropy(queryRaw);
    if (queryRaw.length >= 120 && entropy >= 4.7) {
      queryEntropyScore += 12;
    } else if (queryRaw.length >= 80 && entropy >= 4.3) {
      queryEntropyScore += 8;
    }
    anomalyScore += queryEntropyScore;
  }

  if (detection.enableSuspiciousCookieDetection !== false) {
    const cookieHeaderMaxLength = Math.max(128, Number(detection.cookieHeaderMaxLength || 2500));
    const cookiePairCount = cookieHeader ? cookieHeader.split(';').map((x) => x.trim()).filter(Boolean).length : 0;
    if (cookieHeader.length > cookieHeaderMaxLength) {
      anomalyScore += 14;
      suspiciousCookieSignal = true;
    }
    if (cookiePairCount >= 30) {
      anomalyScore += 8;
      suspiciousCookieSignal = true;
    }
    if (/(%0d|%0a|\r|\n|%00|\x00)/i.test(cookieHeader)) {
      anomalyScore += 10;
      suspiciousCookieSignal = true;
    }
  }

  if (detection.enableHeaderFloodDetection !== false) {
    const headerCountMax = Math.max(8, Number(detection.headerCountMax || 48));
    if (headerCount > headerCountMax) {
      anomalyScore += 14;
      headerFloodSignal = true;
    }
    if (headerCount > Math.floor(headerCountMax * 1.5)) {
      anomalyScore += 6;
      headerFloodSignal = true;
    }
  }

  const authTargetPath = /\/(login|signin|auth|oauth|token|session|password|reset|verify)\b/i.test(path);
  if (authTargetPath && ['POST', 'PUT', 'PATCH'].includes(method)) {
    authTargetingScore += 8;
    if (!hasReferer) authTargetingScore += 3;
    if (!acceptLanguage) authTargetingScore += 4;
    if (!secFetchSite) authTargetingScore += 3;
    if (contentLength > 0 && contentLength < 20) authTargetingScore += 4;
  }
  anomalyScore += Math.min(12, authTargetingScore);

  return {
    anomalyScore,
    spoofScore,
    authTargetingScore,
    queryEntropyScore,
    requestSmugglingSignal,
    suspiciousCookieSignal,
    headerFloodSignal,
    headerCount,
    cookieHeaderLength: cookieHeader.length,
  };
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
export function detectAttackPatterns(request, detection = {}) {
  const url = new URL(request.url);
  const rawPath = url.pathname + url.search;
  const fullPath = safeDecode(rawPath).toLowerCase();
  const decodedQuery = safeDecode(url.search).toLowerCase();
  const mergedPayload = `${fullPath} ${decodedQuery}`;
  const flags = [];
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const cookieHeader = String(request.headers.get('cookie') || '');
  const headerCount = getHeaderCount(request.headers);
  const customSqliPatterns = normalizeList(detection.customSqliPatterns || []);
  const customXssPatterns = normalizeList(detection.customXssPatterns || []);
  const customAttackPathPatterns = normalizeList(detection.customAttackPathPatterns || []);
  const cookieHeaderMaxLength = Math.max(128, Number(detection.cookieHeaderMaxLength || 2500));
  const headerCountMax = Math.max(8, Number(detection.headerCountMax || 48));

  if (LISTS.path_traversal_patterns.some(p => fullPath.includes(p)) || customAttackPathPatterns.some((p) => fullPath.includes(p))) flags.push('PATH_TRAVERSAL');

  const qs = decodedQuery;
  if (qs && (LISTS.sqli_patterns.some(p => qs.includes(p)) || customSqliPatterns.some((p) => qs.includes(p)))) flags.push('SQLI');
  if (qs && (LISTS.xss_patterns.some(p => qs.includes(p)) || customXssPatterns.some((p) => qs.includes(p)))) flags.push('XSS');

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

  const reconPaths = [
    '/.env', '/.git/config', '/.git/heads', '/phpmyadmin', '/wp-admin', '/wp-login.php',
    '/server-status', '/actuator', '/hudson', '/jenkins', '/boaform/admin/formlogin',
    '/vendor/phpunit', '/xmlrpc.php', '/autodiscover/autodiscover.xml', '/w00tw00t',
  ];
  if (reconPaths.some((p) => fullPath === p || fullPath.startsWith(p + '/') || fullPath.includes(p + '?'))) {
    flags.push('RECON_SCAN');
  }

  if (SCANNER_UA_REGEX.test(ua)) {
    flags.push('SCANNER_UA');
  }

  if (SCANNER_PATH_REGEX.test(fullPath)) flags.push('SCANNER_PATH');
  if (INJECTION_PATTERN_REGEX.test(fullPath)) flags.push('INJECTION_PROBE');
  if (detection.enableHeaderInjectionDetection !== false && HEADER_INJECTION_REGEX.test(rawPath)) flags.push('HEADER_INJECTION');
  if (detection.enableSsrfDetection !== false && /(?:^|[?&](?:url|uri|target|dest|redirect|next|callback|endpoint|proxy)=)/i.test(decodedQuery) && SSRF_PATTERN_REGEX.test(decodedQuery)) {
    flags.push('SSRF_PROBE');
  }
  if (detection.enableGraphqlIntrospectionDetection !== false && (url.pathname.toLowerCase().includes('/graphql') || decodedQuery.includes('graphql')) && GRAPHQL_INTROSPECTION_REGEX.test(decodedQuery)) {
    flags.push('GRAPHQL_INTROSPECTION');
  }
  if (detection.enableJwtNoneDetection !== false && hasJwtNoneAlgorithm(request)) {
    flags.push('JWT_NONE_ALG');
  }
  if (detection.enableTemplateInjectionDetection !== false && TEMPLATE_INJECTION_REGEX.test(mergedPayload)) {
    flags.push('TEMPLATE_INJECTION');
  }
  if (detection.enableShellPayloadDetection !== false && SHELL_PAYLOAD_REGEX.test(mergedPayload)) {
    flags.push('SHELL_PAYLOAD');
  }
  if (detection.enableMethodOverrideDetection !== false && hasMethodOverrideAbuse(request)) {
    flags.push('METHOD_OVERRIDE_ABUSE');
  }
  if (detection.enableSuspiciousCookieDetection !== false) {
    const cookiePairCount = cookieHeader ? cookieHeader.split(';').map((x) => x.trim()).filter(Boolean).length : 0;
    if (cookieHeader.length > cookieHeaderMaxLength || cookiePairCount >= 30 || /(%0d|%0a|\r|\n|%00|\x00)/i.test(cookieHeader)) {
      flags.push('COOKIE_ABUSE');
    }
  }
  if (detection.enableHeaderFloodDetection !== false && headerCount > headerCountMax) {
    flags.push('HEADER_FLOOD');
  }

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
  const botSignalScore = Number(signals.botSignalScore || 0);
  const scannerSignalScore = Number(signals.scannerSignalScore || 0);
  const spoofScore = Number(signals.spoofScore || 0);
  const attackFlags = Array.isArray(signals.attackFlags) ? signals.attackFlags : [];

  if (signals.ddosSuspect) return 'ddos';
  if (signals.aiCrawler) return 'ai-crawler';
  if (spoofScore >= 18) return 'automation-bot';
  if (signals.headless) return 'automation-bot';
  if (scannerSignalScore >= 35) return 'bot';
  if (attackFlags.includes('SCANNER_UA') || attackFlags.includes('SCANNER_PATH')) return 'bot';
  if (botSignalScore >= 32) return 'bot';
  if (signals.suspicious && hasRobotWord) return 'robot';
  if (signals.suspicious && hasCrawlerWord) return 'crawler';
  if (signals.suspicious) return 'bot';
  if (hasCrawlerWord || hasRobotWord) return 'crawler';
  if (hasBrowserWord && signals.headerPresenceScore >= 5) return 'user';
  return 'unknown';
}

// ─── Build Detection Signals ─────────────────────────────────────
export function buildDetectionSignals(request, ip, nowMs, behaviorRisk = {}, policy = {}) {
  const url = new URL(request.url);
  const asn = String(request.cf?.asn || 'N/A');
  const detection = getDetectionConfig(policy);
  const customVpnHints = mergeHints(policy?.extraVpnHints || [], detection.customVpnAsnHints || []);
  const customAiPatterns = normalizeList(detection.customAiCrawlerPatterns || []);
  const headerPresenceScore = getHeaderPresenceScore(request);
  const automationSignals = evaluateAutomationSignals(request, headerPresenceScore, detection);
  const requestAnomalies = evaluateRequestAnomalies(request, detection);
  const scannerHeuristics = evaluateScannerHeuristics(request, detection);
  const datacenterAutomation = isLikelyDatacenterAutomation(request, nowMs);
  const suspicious = isSuspicious(request)
    || datacenterAutomation
    || (automationSignals.botSignalScore + scannerHeuristics.scannerHeuristicScore * 0.35) >= 30
    || (automationSignals.scannerSignalScore + scannerHeuristics.scannerHeuristicScore) >= 28
    || requestAnomalies.spoofScore >= 10
    || requestAnomalies.anomalyScore >= 13
    || requestAnomalies.requestSmugglingSignal
    || requestAnomalies.suspiciousCookieSignal
    || requestAnomalies.headerFloodSignal
    || requestAnomalies.authTargetingScore >= 12
    || scannerHeuristics.headerInjection
    || scannerHeuristics.templateInjection
    || scannerHeuristics.shellPayload
    || scannerHeuristics.methodOverrideAbuse;
  const headless = isHeadless(request);
  const vpn = isVpnProxy(request, nowMs, customVpnHints) || datacenterAutomation;
  const aiCrawler = isAiCrawler(request, nowMs, customAiPatterns)
    || automationSignals.aiSignalScore >= 35
    || (automationSignals.aiSignalScore >= 25 && scannerHeuristics.scannerPath)
    || (automationSignals.aiSignalScore >= 20 && automationSignals.scannerSignalScore >= 20)
    || requestAnomalies.anomalyScore >= 18
    || (scannerHeuristics.graphqlIntrospection && automationSignals.aiSignalScore >= 12);
  const spam = isSpam(ip, nowMs);
  const hardBlocked = isHardBlocked(ip, nowMs);
  const attackFlags = detectAttackPatterns(request, detection);
  const trafficBurst = detectTrafficBurst(ip, nowMs, asn);
  const tlsAnalysis = analyzeTls(request);
  const fpHash = behaviorRisk._fpHash || '';
  const fpSpam = isFpSpam(fpHash, nowMs);
  const fpHardBlocked = isFpHardBlocked(fpHash, nowMs);
  const requestPattern = analyzeRequestPattern(ip, url.pathname, url.search, nowMs, request.method, {
    enablePathSprayDetection: detection.enablePathSprayDetection !== false,
    enableNonGetBurstDetection: detection.enableNonGetBurstDetection !== false,
  });

  const ddosSuspect =
    trafficBurst.ddosSuspect ||
    (spam && headerPresenceScore <= 2) ||
    (attackFlags.length >= 2 && trafficBurst.prefixBurst) ||
    (trafficBurst.prefixBurst && (automationSignals.botSignalScore >= 24 || scannerHeuristics.scannerHeuristicScore >= 25)) ||
    (trafficBurst.asnBurst && (spam || fpSpam || automationSignals.botSignalScore >= 18));

  const clientType = classifyClientType(request, {
    suspicious,
    headless,
    aiCrawler,
    ddosSuspect,
    headerPresenceScore,
    botSignalScore: automationSignals.botSignalScore,
    scannerSignalScore: automationSignals.scannerSignalScore + scannerHeuristics.scannerHeuristicScore,
    spoofScore: requestAnomalies.spoofScore,
    attackFlags,
  });

  const result = {
    suspicious, headless, vpn, aiCrawler, spam, hardBlocked,
    datacenterAutomation,
    attackFlags, headerPresenceScore, ddosSuspect, clientType,
    ipRate: trafficBurst.ipRate,
    prefixRate: trafficBurst.prefixRate,
    asnRate: trafficBurst.asnRate,
    asnBurst: trafficBurst.asnBurst,
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
    botSignalScore: automationSignals.botSignalScore,
    aiSignalScore: automationSignals.aiSignalScore,
    scannerSignalScore: automationSignals.scannerSignalScore + scannerHeuristics.scannerHeuristicScore,
    anomalyScore: requestAnomalies.anomalyScore,
    spoofScore: requestAnomalies.spoofScore,
    scannerHeuristicScore: scannerHeuristics.scannerHeuristicScore,
    scannerPath: scannerHeuristics.scannerPath,
    injectionLike: scannerHeuristics.injectionLike,
    ssrfProbe: scannerHeuristics.ssrfProbe,
    graphqlIntrospection: scannerHeuristics.graphqlIntrospection,
    headerInjection: scannerHeuristics.headerInjection,
    authTargetingScore: requestAnomalies.authTargetingScore,
    queryEntropyScore: requestAnomalies.queryEntropyScore,
    requestSmugglingSignal: requestAnomalies.requestSmugglingSignal,
    suspiciousCookieSignal: requestAnomalies.suspiciousCookieSignal,
    headerFloodSignal: requestAnomalies.headerFloodSignal,
    headerCount: requestAnomalies.headerCount,
    cookieHeaderLength: requestAnomalies.cookieHeaderLength,
    patternScore: requestPattern.patternScore,
    identicalPathBurst: requestPattern.identicalPathBurst,
    paramEnumeration: requestPattern.paramEnumeration,
    pathSpray: requestPattern.pathSpray,
    nonGetBurst: requestPattern.nonGetBurst,
    templateInjection: scannerHeuristics.templateInjection,
    shellPayload: scannerHeuristics.shellPayload,
    methodOverrideAbuse: scannerHeuristics.methodOverrideAbuse,
  };

  // Learn only from stronger confidence outcomes to avoid noisy poisoning.
  if (
    result.ddosSuspect
    || result.aiCrawler
    || result.headless
    || result.scannerSignalScore >= 35
    || result.attackFlags.length >= 2
    || result.spoofScore >= 16
    || result.requestSmugglingSignal
    || result.authTargetingScore >= 14
    || result.ssrfProbe
    || result.templateInjection
    || result.shellPayload
    || result.methodOverrideAbuse
    || result.suspiciousCookieSignal
    || result.headerFloodSignal
  ) {
    rememberEmergingSignatures(request, result, nowMs);
  }

  return result;
}

// ─── Weighted AI-Like Threat Scoring ─────────────────────────────
export function computeThreatScore(request, signals, policy = {}) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const detection = getDetectionConfig(policy);
  const botWeight = Number(detection.botSignalWeight || 0.45);
  const aiWeight = Number(detection.aiSignalWeight || 0.5);
  const scannerWeight = Number(detection.scannerSignalWeight || 0.55);
  const anomalyWeight = Number(detection.anomalySignalWeight || 0.45);
  const spoofWeight = Number(detection.spoofSignalWeight || 0.55);

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
    ipRate = 0, prefixRate = 0, asnRate = 0, asnBurst = false,
    fpRisk = 0, asnRisk = 0, countryRisk = 0, bypassAttempts = 0,
    isBotFarm = false, countryAnomaly = false,
    tlsScore = 0, tlsSignals = [],
    fpSpam = false, fpHardBlocked = false,
    botSignalScore = 0, aiSignalScore = 0,
    scannerSignalScore = 0,
    scannerHeuristicScore = 0,
    anomalyScore = 0, spoofScore = 0,
    authTargetingScore = 0, queryEntropyScore = 0, requestSmugglingSignal = false,
    suspiciousCookieSignal = false, headerFloodSignal = false,
    headerCount = 0, cookieHeaderLength = 0,
    identicalPathBurst = false, paramEnumeration = false,
    pathSpray = false, nonGetBurst = false,
    ssrfProbe = false, graphqlIntrospection = false, headerInjection = false,
    templateInjection = false, shellPayload = false, methodOverrideAbuse = false,
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
  behaviorScore += Math.min(25, Math.round(botSignalScore * botWeight));
  behaviorScore += Math.min(20, Math.round(aiSignalScore * aiWeight));
  behaviorScore += Math.min(24, Math.round(scannerSignalScore * scannerWeight));
  behaviorScore += Math.min(18, Math.round(scannerHeuristicScore * 0.35));
  behaviorScore += Math.min(16, Math.round(anomalyScore * anomalyWeight));
  behaviorScore += Math.min(18, Math.round(spoofScore * spoofWeight));
  behaviorScore += Math.min(14, Math.round(authTargetingScore * 0.8));
  behaviorScore += Math.min(10, Math.round(queryEntropyScore * 0.7));
  if (ddosSuspect) behaviorScore += 35;
  if (fpSpam) behaviorScore += 15;
  if (fpHardBlocked) behaviorScore += 20;
  if (requestSmugglingSignal) behaviorScore += 12;
  if (ssrfProbe) behaviorScore += 10;
  if (templateInjection) behaviorScore += 10;
  if (shellPayload) behaviorScore += 12;
  if (methodOverrideAbuse) behaviorScore += 8;
  if (suspiciousCookieSignal) behaviorScore += 8;
  if (headerFloodSignal) behaviorScore += 10;
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
  if (asnRate >= DDOS_ASN_THRESHOLD) networkScore += 12;
  if (asnBurst) networkScore += 10;
  networkScore += Math.min(20, tlsScore);
  if (requestSmugglingSignal) networkScore += 8;
  if (headerFloodSignal) networkScore += 6;
  if (headerCount >= 64) networkScore += 4;
  if (cookieHeaderLength >= 4096) networkScore += 6;
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
  if (attackFlags.includes('RECON_SCAN')) attackScore += 18;
  if (attackFlags.includes('SCANNER_UA')) attackScore += 15;
  if (attackFlags.includes('SCANNER_PATH')) attackScore += 12;
  if (attackFlags.includes('INJECTION_PROBE')) attackScore += 20;
  if (attackFlags.includes('SSRF_PROBE')) attackScore += 32;
  if (attackFlags.includes('GRAPHQL_INTROSPECTION')) attackScore += 16;
  if (attackFlags.includes('HEADER_INJECTION')) attackScore += 22;
  if (attackFlags.includes('JWT_NONE_ALG')) attackScore += 30;
  if (attackFlags.includes('TEMPLATE_INJECTION')) attackScore += 28;
  if (attackFlags.includes('SHELL_PAYLOAD')) attackScore += 36;
  if (attackFlags.includes('METHOD_OVERRIDE_ABUSE')) attackScore += 18;
  if (attackFlags.includes('COOKIE_ABUSE')) attackScore += 16;
  if (attackFlags.includes('HEADER_FLOOD')) attackScore += 14;
  if (headerInjection) attackScore += 8;
  if (graphqlIntrospection) attackScore += 6;
  if (templateInjection) attackScore += 8;
  if (shellPayload) attackScore += 10;

  // ── Pattern Score ──
  patternScore += (signals.patternScore || 0);
  if (identicalPathBurst) patternScore += 5;
  if (paramEnumeration) patternScore += 5;
  if (pathSpray) patternScore += 6;
  if (nonGetBurst) patternScore += 6;

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
  if (requestSmugglingSignal && attackFlags.length > 0) finalScore += 8;

  if (request.cf?.botManagement?.verifiedBot && !attackFlags.length && !ddosSuspect && !suspicious) {
    finalScore -= 22;
  }

  return Math.max(0, Math.min(finalScore, 100));
}

// ─── Challenge Escalation ────────────────────────────────────────
// Determines what action to take based on threat score
export function determineEscalation(threatScore, signals, policy = {}) {
  const detection = getDetectionConfig(policy);
  const blockThreshold = Number(detection.scoreBlockThreshold || 85);
  const powHardThreshold = Number(detection.scorePowHardThreshold || 60);
  const powThreshold = Number(detection.scorePowThreshold || 30);
  const powLiteThreshold = Number(detection.scorePowLiteThreshold || 15);

  // very high → hard block
  if (threatScore >= blockThreshold) return 'block';
  if (signals.isBotFarm) return 'block';
  if (signals.fpHardBlocked) return 'block';
  if (signals.requestSmugglingSignal && (signals.attackFlags || []).length > 0) return 'block';
  if (signals.shellPayload && (signals.attackFlags || []).length > 0) return 'block';
  if (signals.spoofScore >= 24 && signals.scannerSignalScore >= 40) return 'block';

  // high → PoW challenge (hard difficulty)
  if (threatScore >= powHardThreshold) return 'pow-hard';
  if (signals.asnBurst && (signals.spam || signals.fpSpam)) return 'pow-hard';
  if (signals.authTargetingScore >= 14 && signals.spoofScore >= 12) return 'pow-hard';
  if (signals.templateInjection || signals.methodOverrideAbuse || signals.headerFloodSignal) return 'pow-hard';

  // medium → standard PoW challenge
  if (threatScore >= powThreshold) return 'pow';

  // low-medium → lightweight JS challenge
  if (threatScore >= powLiteThreshold) return 'pow-lite';

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
