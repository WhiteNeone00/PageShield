/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Utility Functions
   ═══════════════════════════════════════════════════════════════════ */

import { PENALTY_STEPS } from './core.config.js';

// ─── String Helpers ──────────────────────────────────────────────
export function clip(value, max = 256) {
  if (!value) return 'N/A';
  const s = String(value);
  return s.length > max ? s.slice(0, max - 3) + '...' : s;
}

export function compactMiddle(value, max = 64) {
  const str = String(value || 'N/A');
  if (str.length <= max) return str;
  const left = Math.ceil((max - 1) / 2);
  const right = Math.floor((max - 1) / 2);
  return str.slice(0, left) + '\u2026' + str.slice(str.length - right);
}

// ─── IP / Network ────────────────────────────────────────────────
export function normalizeIp(ip) {
  if (!ip) return '';
  const raw = String(ip).trim();
  if (!raw || raw === 'N/A') return '';
  return raw.startsWith('::ffff:') ? raw.slice(7) : raw;
}

export function getClientIp(req) {
  return req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'N/A';
}

export function getIpPrefix(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return 'unknown';
  if (normalized.includes(':')) {
    return normalized.split(':').slice(0, 4).join(':') + '::/64';
  }
  const parts = normalized.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  return normalized;
}

export function parseIpListPayload(payload) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.ips)) return payload.ips;
  if (typeof payload === 'string') {
    return payload.split(/\r?\n|,/).map((s) => s.trim()).filter(Boolean);
  }
  return [];
}

// ─── Cookie Parsing ──────────────────────────────────────────────
export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return out;
}

// ─── Crypto Helpers ──────────────────────────────────────────────
function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256(value) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value || '')));
  return toHex(buf);
}

// ─── Security Headers ───────────────────────────────────────────
export function securityHeaders(h) {
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  h.set('X-XSS-Protection', '1; mode=block');
  h.set('X-Shield', 'Ryzeon Shield v3');
  return h;
}

// ─── Threat Display ─────────────────────────────────────────────
export function severityLabel(score) {
  if (score >= 70) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 30) return 'Medium';
  return 'Low';
}



export function threatBar(score) {
  const filled = Math.round(score / 10);
  return '\u2588'.repeat(filled) + '\u2591'.repeat(10 - filled);
}

// ─── Penalty Label ──────────────────────────────────────────────
export function penaltyLabel(level, permanent) {
  if (permanent) return 'permanent';
  const seconds = PENALTY_STEPS[Math.min(level, PENALTY_STEPS.length - 1)] || 0;
  if (seconds < 0) return 'permanent';
  if (seconds % 86400 === 0) return `${seconds / 86400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  return `${seconds / 60}m`;
}

// ─── List Normalization ─────────────────────────────────────────
export function normalizeStringList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item || '').trim().toLowerCase()).filter(Boolean))];
}
