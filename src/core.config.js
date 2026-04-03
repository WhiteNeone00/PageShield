/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Configuration & Constants
   ═══════════════════════════════════════════════════════════════════ */

// ─── Cookie Names ────────────────────────────────────────────────
export const COOKIE_NAME = 'cf_shield';
export const COOKIE_EXP_NAME = 'cf_shield_exp';
export const COOKIE_SIG_NAME = 'cf_shield_sig';
export const COOKIE_FP_NAME = 'cf_fp';
export const COOKIE_RISK_NAME = 'cf_risk';

// ─── Limits & Thresholds ─────────────────────────────────────────
export const COOKIE_MAX_AGE = 3600; // 1h exact verify expiry
export const SPAM_WINDOW_MS = 60 * 1000;
export const SPAM_LIMIT = 20;
export const HARD_BLOCK_LIMIT = 60;
export const POW_DIFFICULTY = 3;
export const LIST_CACHE_TTL = 3600;
export const BLACKLIST_CACHE_TTL = 600;
export const TRAFFIC_WINDOW_MS = 10 * 1000;
export const DDOS_IP_THRESHOLD = 80;
export const DDOS_PREFIX_THRESHOLD = 300;
export const DDOS_ASN_THRESHOLD = 420;
export const DDOS_BYTES_PER_REQUEST_EST = 12 * 1024;
export const CHALLENGE_NONCE_TTL = 120;

// ─── Progressive Penalty Ladder ──────────────────────────────────
// 5m → 10m → 30m → 1h → 3h → 6h → 12h → 1d → 15d → 30d → permanent
export const PENALTY_STEPS = [
  5 * 60,
  10 * 60,
  30 * 60,
  60 * 60,
  3 * 60 * 60,
  6 * 60 * 60,
  12 * 60 * 60,
  24 * 60 * 60,
  15 * 24 * 60 * 60,
  30 * 24 * 60 * 60,
  -1,
];

// ─── Required Remote List Keys ───────────────────────────────────
export const REQUIRED_LIST_KEYS = [
  'bot_ua_patterns',
  'headless_hints',
  'ai_crawler_patterns',
  'vpn_asn_hints',
  'honeypot_paths',
  'sqli_patterns',
  'xss_patterns',
  'path_traversal_patterns',
];

// ─── Webhook / Discord ──────────────────────────────────────────
export const DEFAULT_LOGO_URL = 'https://cdn.ryzeon.wtf/logo.webp';

export const WEBHOOK_COLORS = {
  PASSED: 0x57F287,
  EXPIRED: 0xFEE75C,
  BLOCKED: 0xED4245,
  FAILED: 0xE67E22,
  HARD_BLOCKED: 0x992D22,
  HONEYPOT: 0xEB459E,
  CHALLENGED: 0x5865F2,
  ATTACK: 0xFF0000,
  ERROR: 0xFFA500,
  DDOS_PREVENTED: 0x00B0F4,
  SYSTEM_UPDATE: 0x8E44AD,
  SYSTEM_DOWN: 0xC0392B,
  SYSTEM_RECOVERED: 0x2ECC71,
  DEPLOYED: 0x2D7D46,
  RATE_LIMITED: 0xE67E22,
  VPN_BLOCKED: 0x9B59B6,
  SUSPENDED: 0x992D22,
  COUNTRY_BLOCKED: 0x546E7A,
  BOT_DETECTED: 0xF39C12,
  AI_CRAWLER: 0x00B4D8,
  BOT_FARM: 0xFF1744,
  HONEYPOT_FORM: 0xEB459E,
};

export const DISCORD_WORTHY = new Set([
  'PASSED', 'BLOCKED', 'HARD_BLOCKED', 'HONEYPOT', 'FAILED', 'EXPIRED', 'ATTACK', 'ERROR',
  'DDOS_PREVENTED', 'SYSTEM_UPDATE', 'SYSTEM_DOWN', 'SYSTEM_RECOVERED', 'DEPLOYED',
  'RATE_LIMITED', 'VPN_BLOCKED', 'SUSPENDED', 'COUNTRY_BLOCKED', 'BOT_DETECTED',
  'AI_CRAWLER', 'BOT_FARM', 'HONEYPOT_FORM',
]);

export const DEFAULT_DETECTION_CONFIG = {
  tokenBucketIpPerSec: 35,
  tokenBucketFpPerSec: 45,
  authWindowSeconds: 5 * 60,
  authWarnIpCount: 8,
  authWarnFpCount: 10,
  authHardIpCount: 20,
  authHardFpCount: 25,
  attackMemoryAutoBlockCount: 25,
  attackMemoryWindowSeconds: 24 * 3600,
  ipReputationAutoBlockScore: 80,
  ipReputationWeight: 0.25,
  scoreBlockThreshold: 85,
  scorePowHardThreshold: 60,
  scorePowThreshold: 30,
  scorePowLiteThreshold: 15,
  botSignalWeight: 0.45,
  aiSignalWeight: 0.5,
  scannerSignalWeight: 0.55,
  anomalySignalWeight: 0.45,
  spoofSignalWeight: 0.55,
  enableSsrfDetection: true,
  enableGraphqlIntrospectionDetection: true,
  enableHeaderInjectionDetection: true,
  enableJwtNoneDetection: true,
  enableEntropyDetection: true,
  enableRequestSmugglingDetection: true,
  enablePathSprayDetection: true,
  enableNonGetBurstDetection: true,
  enableTemplateInjectionDetection: true,
  enableShellPayloadDetection: true,
  enableMethodOverrideDetection: true,
  enableSuspiciousCookieDetection: true,
  enableHeaderFloodDetection: true,
  cookieHeaderMaxLength: 2500,
  headerCountMax: 48,
  customScannerUaPatterns: [],
  customAttackPathPatterns: [],
  customSqliPatterns: [],
  customXssPatterns: [],
  customVpnAsnHints: [],
  customAiCrawlerPatterns: [],
};

function normalizeStringList(value) {
  const list = Array.isArray(value)
    ? value
    : String(value || '').split(',');
  return [...new Set(list.map((x) => String(x || '').trim().toLowerCase()).filter(Boolean))];
}

function clampNum(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function normalizeDetectionConfig(raw = {}) {
  const input = raw && typeof raw === 'object' ? raw : {};
  return {
    tokenBucketIpPerSec: clampNum(input.tokenBucketIpPerSec, 5, 500, DEFAULT_DETECTION_CONFIG.tokenBucketIpPerSec),
    tokenBucketFpPerSec: clampNum(input.tokenBucketFpPerSec, 5, 800, DEFAULT_DETECTION_CONFIG.tokenBucketFpPerSec),
    authWindowSeconds: clampNum(input.authWindowSeconds, 60, 3600, DEFAULT_DETECTION_CONFIG.authWindowSeconds),
    authWarnIpCount: clampNum(input.authWarnIpCount, 1, 200, DEFAULT_DETECTION_CONFIG.authWarnIpCount),
    authWarnFpCount: clampNum(input.authWarnFpCount, 1, 300, DEFAULT_DETECTION_CONFIG.authWarnFpCount),
    authHardIpCount: clampNum(input.authHardIpCount, 1, 500, DEFAULT_DETECTION_CONFIG.authHardIpCount),
    authHardFpCount: clampNum(input.authHardFpCount, 1, 800, DEFAULT_DETECTION_CONFIG.authHardFpCount),
    attackMemoryAutoBlockCount: clampNum(input.attackMemoryAutoBlockCount, 1, 300, DEFAULT_DETECTION_CONFIG.attackMemoryAutoBlockCount),
    attackMemoryWindowSeconds: clampNum(input.attackMemoryWindowSeconds, 300, 30 * 24 * 3600, DEFAULT_DETECTION_CONFIG.attackMemoryWindowSeconds),
    ipReputationAutoBlockScore: clampNum(input.ipReputationAutoBlockScore, 20, 200, DEFAULT_DETECTION_CONFIG.ipReputationAutoBlockScore),
    ipReputationWeight: clampNum(input.ipReputationWeight, 0, 1, DEFAULT_DETECTION_CONFIG.ipReputationWeight),
    scoreBlockThreshold: clampNum(input.scoreBlockThreshold, 35, 100, DEFAULT_DETECTION_CONFIG.scoreBlockThreshold),
    scorePowHardThreshold: clampNum(input.scorePowHardThreshold, 20, 99, DEFAULT_DETECTION_CONFIG.scorePowHardThreshold),
    scorePowThreshold: clampNum(input.scorePowThreshold, 5, 95, DEFAULT_DETECTION_CONFIG.scorePowThreshold),
    scorePowLiteThreshold: clampNum(input.scorePowLiteThreshold, 0, 90, DEFAULT_DETECTION_CONFIG.scorePowLiteThreshold),
    botSignalWeight: clampNum(input.botSignalWeight, 0, 2, DEFAULT_DETECTION_CONFIG.botSignalWeight),
    aiSignalWeight: clampNum(input.aiSignalWeight, 0, 2, DEFAULT_DETECTION_CONFIG.aiSignalWeight),
    scannerSignalWeight: clampNum(input.scannerSignalWeight, 0, 2, DEFAULT_DETECTION_CONFIG.scannerSignalWeight),
    anomalySignalWeight: clampNum(input.anomalySignalWeight, 0, 2, DEFAULT_DETECTION_CONFIG.anomalySignalWeight),
    spoofSignalWeight: clampNum(input.spoofSignalWeight, 0, 2, DEFAULT_DETECTION_CONFIG.spoofSignalWeight),
    enableSsrfDetection: input.enableSsrfDetection !== false,
    enableGraphqlIntrospectionDetection: input.enableGraphqlIntrospectionDetection !== false,
    enableHeaderInjectionDetection: input.enableHeaderInjectionDetection !== false,
    enableJwtNoneDetection: input.enableJwtNoneDetection !== false,
    enableEntropyDetection: input.enableEntropyDetection !== false,
    enableRequestSmugglingDetection: input.enableRequestSmugglingDetection !== false,
    enablePathSprayDetection: input.enablePathSprayDetection !== false,
    enableNonGetBurstDetection: input.enableNonGetBurstDetection !== false,
    enableTemplateInjectionDetection: input.enableTemplateInjectionDetection !== false,
    enableShellPayloadDetection: input.enableShellPayloadDetection !== false,
    enableMethodOverrideDetection: input.enableMethodOverrideDetection !== false,
    enableSuspiciousCookieDetection: input.enableSuspiciousCookieDetection !== false,
    enableHeaderFloodDetection: input.enableHeaderFloodDetection !== false,
    cookieHeaderMaxLength: clampNum(input.cookieHeaderMaxLength, 256, 32768, DEFAULT_DETECTION_CONFIG.cookieHeaderMaxLength),
    headerCountMax: clampNum(input.headerCountMax, 8, 256, DEFAULT_DETECTION_CONFIG.headerCountMax),
    customScannerUaPatterns: normalizeStringList(input.customScannerUaPatterns || []),
    customAttackPathPatterns: normalizeStringList(input.customAttackPathPatterns || []),
    customSqliPatterns: normalizeStringList(input.customSqliPatterns || []),
    customXssPatterns: normalizeStringList(input.customXssPatterns || []),
    customVpnAsnHints: normalizeStringList(input.customVpnAsnHints || []),
    customAiCrawlerPatterns: normalizeStringList(input.customAiCrawlerPatterns || []),
  };
}

// ─── Default Protection Policy ───────────────────────────────────
export const DEFAULT_POLICY = {
  protectEnabled: true,
  rateLimitEnabled: true,
  attackBlockEnabled: true,
  honeypotEnabled: true,
  aiCrawlerBlockEnabled: true,
  ddosBlockEnabled: true,
  vpnBlockEnabled: true,
  extraHoneypotPaths: [],
  extraVpnHints: [],
  detection: { ...DEFAULT_DETECTION_CONFIG },
};

export function normalizeShieldPolicy(raw = {}) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const merged = {
    ...DEFAULT_POLICY,
    ...input,
    detection: {
      ...DEFAULT_DETECTION_CONFIG,
      ...(input.detection && typeof input.detection === 'object' ? input.detection : {}),
    },
  };

  const normalized = {
    protectEnabled: merged.protectEnabled !== false,
    rateLimitEnabled: merged.rateLimitEnabled !== false,
    attackBlockEnabled: merged.attackBlockEnabled !== false,
    honeypotEnabled: merged.honeypotEnabled !== false,
    aiCrawlerBlockEnabled: merged.aiCrawlerBlockEnabled !== false,
    ddosBlockEnabled: merged.ddosBlockEnabled !== false,
    vpnBlockEnabled: merged.vpnBlockEnabled !== false,
    extraHoneypotPaths: normalizeStringList(merged.extraHoneypotPaths || []),
    extraVpnHints: normalizeStringList(merged.extraVpnHints || []),
    detection: normalizeDetectionConfig(merged.detection),
  };

  // Ensure escalation thresholds are ordered
  if (normalized.detection.scorePowLiteThreshold > normalized.detection.scorePowThreshold) {
    normalized.detection.scorePowLiteThreshold = normalized.detection.scorePowThreshold;
  }
  if (normalized.detection.scorePowThreshold > normalized.detection.scorePowHardThreshold) {
    normalized.detection.scorePowThreshold = normalized.detection.scorePowHardThreshold;
  }
  if (normalized.detection.scorePowHardThreshold > normalized.detection.scoreBlockThreshold) {
    normalized.detection.scorePowHardThreshold = normalized.detection.scoreBlockThreshold;
  }

  return normalized;
}

// ─── Shared KV Key Constants ─────────────────────────────────────
export const BLACKLIST_KEY = 'remote:blacklisted_ips';
export const WHITELIST_EXTRA_KEY = 'shield:whitelist:extra';
export const POLICY_KEY = 'shield:config:policy';
