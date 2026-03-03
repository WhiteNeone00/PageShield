/* ═══════════════════════════════════════════════════════════════════
   Ryzeon Shield v3 — Behavior Profiling, IP Reputation & Threat Intelligence
   Fingerprint reuse detection, self-learning IP reputation,
   behavioral analysis scoring, geo+ASN intelligence
   ═══════════════════════════════════════════════════════════════════ */

import { kvGetJson, kvPutJson } from './core.storage.js';

// ─── Constants ───────────────────────────────────────────────────
const FP_MAX_IPS = 50;              // if 1 fingerprint seen from >= this many IPs → bot farm
const IP_REP_PASS_BONUS = -2;       // reputation improves on pass
const IP_REP_BLOCK_PENALTY = 8;     // reputation worsens on block
const IP_REP_ATTACK_PENALTY = 20;   // reputation worsens on attack
const IP_REP_HONEYPOT_PENALTY = 50; // reputation worsens on honeypot
const IP_REP_TRUST_THRESHOLD = -10; // auto-trust below this
const IP_REP_BLOCK_THRESHOLD = 80;  // auto-block above this

// ─── Store Behavior Profile ─────────────────────────────────────
export async function storeBehaviorProfile(env, details) {
  if (!env?.SHIELD_KV) return null;
  const fp = String(details.fpHash || '').slice(0, 64);
  if (!fp) return null;
  const key = `shield:profile:fp:${fp}`;
  const prev = (await kvGetJson(env, key)) || {
    fp,
    seen: 0,
    blocked: 0,
    failedChallenge: 0,
    passedChallenge: 0,
    lastIp: 'N/A',
    lastAsn: 'N/A',
    lastCountry: 'N/A',
    labels: {},
    ips: [],
    countries: [],
    asns: [],
    behaviorScores: [],
  };
  prev.seen += 1;
  prev.lastIp = details.ip || prev.lastIp;
  prev.lastAsn = details.asn || prev.lastAsn;
  prev.lastCountry = details.country || prev.lastCountry;

  // Track unique IPs for fingerprint reuse detection
  const ipList = Array.isArray(prev.ips) ? prev.ips : [];
  if (details.ip && !ipList.includes(details.ip)) {
    ipList.push(details.ip);
    if (ipList.length > 200) ipList.splice(0, ipList.length - 200);
  }
  prev.ips = ipList;
  prev.uniqueIps = ipList.length;
  prev.isBotFarm = ipList.length >= FP_MAX_IPS;

  // Track countries for geo-anomaly detection
  const countryList = Array.isArray(prev.countries) ? prev.countries : [];
  if (details.country && details.country !== 'N/A' && !countryList.includes(details.country)) {
    countryList.push(details.country);
    if (countryList.length > 50) countryList.splice(0, countryList.length - 50);
  }
  prev.countries = countryList;
  prev.countryChangeDetected = countryList.length > 3;

  // Track ASNs
  const asnList = Array.isArray(prev.asns) ? prev.asns : [];
  if (details.asn && details.asn !== 'N/A' && !asnList.includes(details.asn)) {
    asnList.push(details.asn);
    if (asnList.length > 50) asnList.splice(0, asnList.length - 50);
  }
  prev.asns = asnList;

  const label = details.event || 'seen';
  prev.labels[label] = (prev.labels[label] || 0) + 1;
  if (label === 'BLOCKED' || label === 'HARD_BLOCKED' || label === 'ATTACK' || label === 'HONEYPOT') prev.blocked += 1;
  if (label === 'FAILED') prev.failedChallenge += 1;
  if (label === 'PASSED') prev.passedChallenge += 1;
  prev.updatedAt = new Date().toISOString();
  await kvPutJson(env, key, prev, 90 * 24 * 3600);

  // Update IP reputation
  if (details.ip && details.ip !== 'N/A') {
    await updateIpReputation(env, details.ip, label);
  }

  return prev;
}

// ─── IP Reputation System (Self-Learning) ────────────────────────
export async function updateIpReputation(env, ip, event) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') return;
  const key = `shield:rep:ip:${ip}`;
  const prev = (await kvGetJson(env, key)) || { score: 0, events: 0, firstSeen: new Date().toISOString() };

  let delta = 0;
  if (event === 'PASSED') delta = IP_REP_PASS_BONUS;
  else if (event === 'BLOCKED' || event === 'HARD_BLOCKED') delta = IP_REP_BLOCK_PENALTY;
  else if (event === 'ATTACK') delta = IP_REP_ATTACK_PENALTY;
  else if (event === 'HONEYPOT') delta = IP_REP_HONEYPOT_PENALTY;
  else if (event === 'FAILED') delta = 5;
  else if (event === 'CHALLENGED') delta = 1;

  prev.score = Math.max(-50, Math.min(200, (prev.score || 0) + delta));
  prev.events = (prev.events || 0) + 1;
  prev.lastEvent = event;
  prev.lastSeen = new Date().toISOString();
  prev.trusted = prev.score <= IP_REP_TRUST_THRESHOLD;
  prev.autoBlock = prev.score >= IP_REP_BLOCK_THRESHOLD;

  await kvPutJson(env, key, prev, 30 * 24 * 3600);
}

// ─── Load IP Reputation ─────────────────────────────────────────
export async function loadIpReputation(env, ip) {
  if (!env?.SHIELD_KV || !ip || ip === 'N/A') return { score: 0, trusted: false, autoBlock: false };
  const data = await kvGetJson(env, `shield:rep:ip:${ip}`);
  if (!data) return { score: 0, trusted: false, autoBlock: false };
  return {
    score: data.score || 0,
    trusted: !!data.trusted,
    autoBlock: !!data.autoBlock,
    events: data.events || 0,
    lastEvent: data.lastEvent || 'none',
  };
}

// ─── Load Behavior Risk ──────────────────────────────────────────
export async function loadBehaviorRisk(env, fpHash, asn, country) {
  const risk = { fpRisk: 0, asnRisk: 0, countryRisk: 0, bypassAttempts: 0, isBotFarm: false, countryAnomaly: false, ipRepScore: 0 };
  if (!env?.SHIELD_KV) return risk;

  if (fpHash) {
    const profile = await kvGetJson(env, `shield:profile:fp:${fpHash}`);
    if (profile) {
      const blocked = Number(profile.blocked || 0);
      const failed = Number(profile.failedChallenge || 0);
      const uniqueIps = Number(profile.uniqueIps || 0);
      risk.fpRisk = Math.min(35, blocked * 4 + failed * 3);
      risk.bypassAttempts = failed;
      risk.isBotFarm = !!profile.isBotFarm || uniqueIps >= FP_MAX_IPS;
      risk.countryAnomaly = !!profile.countryChangeDetected;
      risk.fpUniqueIps = uniqueIps;
      risk.fpCountries = (profile.countries || []).length;

      // Bot farm detection adds massive risk
      if (risk.isBotFarm) risk.fpRisk = 35;
      // Country anomaly adds risk
      if (risk.countryAnomaly) risk.fpRisk = Math.min(35, risk.fpRisk + 10);
    }
  }

  if (asn && asn !== 'N/A') {
    const asnIntel = await kvGetJson(env, `shield:intel:asn:${asn}`);
    if (asnIntel?.bad) risk.asnRisk = Math.min(20, Number(asnIntel.bad || 0) * 2);
  }

  if (country && country !== 'N/A') {
    const ccIntel = await kvGetJson(env, `shield:intel:cc:${country}`);
    if (ccIntel?.bad) risk.countryRisk = Math.min(15, Number(ccIntel.bad || 0));
  }

  return risk;
}

// ─── Score Client Behavioral Signals ─────────────────────────────
export function scoreBehavior(behaviorData) {
  if (!behaviorData) return { behaviorScore: 0, isHuman: null, signals: [] };

  const signals = [];
  let score = 0;

  const {
    mouseCount = 0, mouseDistance = 0, mouseDensity = 0,
    clicks = 0, avgClickInterval = 0,
    scrollEvents = 0, keyPresses = 0, avgKeyInterval = 0,
    touchCount = 0, focusChanges = 0, pasteCount = 0,
    duration = 0,
  } = behaviorData;

  const durationSec = duration / 1000;

  // No mouse movement at all (bot signal)
  if (mouseCount === 0 && touchCount === 0 && durationSec > 3) {
    score += 15;
    signals.push('no_interaction');
  }

  // Too-perfect click timing (bot signal)
  if (clicks >= 3 && avgClickInterval > 0 && avgClickInterval < 50) {
    score += 12;
    signals.push('rapid_clicks');
  }

  // Zero mouse distance but high count (bot sending fake events)
  if (mouseCount > 20 && mouseDistance < 10) {
    score += 10;
    signals.push('fake_mouse');
  }

  // Extremely fast completion (less than 2s with interaction)
  if (durationSec < 2 && (mouseCount > 0 || clicks > 0)) {
    score += 8;
    signals.push('too_fast');
  }

  // Paste attempt in hidden fields
  if (pasteCount > 0) {
    score += 5;
    signals.push('paste_detected');
  }

  // Keyboard used on challenge page (suspicious unless typing in honeypot)
  if (keyPresses > 5) {
    score += 3;
    signals.push('typing_on_challenge');
  }

  // Very regular mouse density (bots move mouse at constant speed)
  if (mouseDensity > 0 && mouseCount > 50 && durationSec > 2) {
    const avgDist = mouseDistance / mouseCount;
    if (avgDist > 0 && avgDist < 2) {
      score += 8;
      signals.push('uniform_mouse');
    }
  }

  // Human signals (reduce score)
  if (mouseCount > 5 && mouseDistance > 100 && durationSec > 3) {
    score -= 5; // natural mouse movement
    signals.push('natural_mouse');
  }
  if (scrollEvents > 0) {
    score -= 2;
    signals.push('scrolled');
  }
  if (focusChanges >= 2) {
    score -= 1; // tab switching is human
    signals.push('tab_switched');
  }

  score = Math.max(0, Math.min(30, score));

  return {
    behaviorScore: score,
    isHuman: score <= 5 ? true : score >= 15 ? false : null,
    signals,
  };
}

// ─── Score Honeypot Traps ────────────────────────────────────────
export function scoreHoneypot(honeypotData) {
  if (!honeypotData) return { honeypotTriggered: false, honeypotScore: 0 };
  const { website = '', email = '' } = honeypotData;
  if (website || email) {
    return { honeypotTriggered: true, honeypotScore: 30 };
  }
  return { honeypotTriggered: false, honeypotScore: 0 };
}

// ─── Update Threat Intelligence ──────────────────────────────────
export async function updateThreatIntel(env, details, isBadEvent) {
  if (!env?.SHIELD_KV) return;
  if (!isBadEvent) return;
  const asn = details.asn;
  const country = details.country;
  if (asn && asn !== 'N/A') {
    const key = `shield:intel:asn:${asn}`;
    const prev = (await kvGetJson(env, key)) || { bad: 0, updatedAt: null };
    prev.bad = Number(prev.bad || 0) + 1;
    prev.updatedAt = new Date().toISOString();
    await kvPutJson(env, key, prev, 30 * 24 * 3600);
  }
  if (country && country !== 'N/A') {
    const key = `shield:intel:cc:${country}`;
    const prev = (await kvGetJson(env, key)) || { bad: 0, updatedAt: null };
    prev.bad = Number(prev.bad || 0) + 1;
    prev.updatedAt = new Date().toISOString();
    await kvPutJson(env, key, prev, 30 * 24 * 3600);
  }
}
