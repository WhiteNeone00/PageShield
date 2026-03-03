/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Cryptographic Operations
   HMAC token signing, verification, fingerprint derivation
   ═══════════════════════════════════════════════════════════════════ */

import { normalizeIp, sha256 } from './core.utils.js';

// ─── HMAC Signing ────────────────────────────────────────────────
export async function hmacSign(secret, data) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hmacVerify(secret, data, signature) {
  const expected = await hmacSign(secret, data);
  return expected === signature;
}

export function getSigningSecret(env) {
  return env?.SHIELD_SECRET || 'ryzeon-default-secret-change-me';
}

// ─── Request Fingerprint Derivation ──────────────────────────────
export async function deriveRequestFingerprint(request, ip) {
  const ua = request.headers.get('user-agent') || '';
  const acceptLang = request.headers.get('accept-language') || '';
  const secUa = request.headers.get('sec-ch-ua') || '';
  const secPlatform = request.headers.get('sec-ch-ua-platform') || '';
  const tls = request.cf?.tlsVersion || 'N/A';
  const http = request.cf?.httpProtocol || 'N/A';
  const basis = [ua, acceptLang, secUa, secPlatform, tls, http, normalizeIp(ip)].join('|');
  return await sha256(basis);
}
