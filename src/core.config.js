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
};

// ─── Shared KV Key Constants ─────────────────────────────────────
export const BLACKLIST_KEY = 'remote:blacklisted_ips';
export const WHITELIST_EXTRA_KEY = 'shield:whitelist:extra';
export const POLICY_KEY = 'shield:config:policy';
