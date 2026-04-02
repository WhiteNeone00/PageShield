# Ryzeon Shield v3 (Cloudflare Worker)

Advanced edge security gateway for `ryzeon.wtf` and subdomains.

Ryzeon Shield v3 combines request intelligence, PoW browser verification, IP reputation, anti-replay challenge validation, and rich telemetry (Discord, D1, R2, external logs).

## Highlights

- HMAC-signed verification cookies with 1-hour expiry
- Dynamic PoW challenge flow (`pow-lite`, `pow`, `pow-hard`)
- Challenge anti-replay protections (IP/fingerprint/timestamp/signature aware)
- Behavioral and honeypot scoring during verify
- TLS/HTTP fingerprinting + request-pattern scoring
- IP reputation learning and auto-block thresholds
- Bot-farm detection (fingerprint reuse across many IPs)
- Country/ASN intelligence integration
- Progressive penalties + permanent bans for canary/honeypot hits
- Discord webhooks with anti-spam dedupe/cooldowns
- D1 event/error logging, R2 event snapshots, KV counters/state

## Architecture

Key files in `src/`:

- `index.js` — main Worker pipeline, verify/challenge logic, policy enforcement
- `engine.detection.js` — signal extraction + weighted threat scoring
- `engine.behavior.js` — profile/reputation/threat intel learning
- `engine.penalties.js` — penalty ladder and blacklist status
- `engine.traffic.js` — rate windows, burst and fingerprint traffic patterns
- `engine.lists.js` — remote security list loading/sanitization/cache
- `middleware.webhooks.js` — Discord, D1, R2, external log transport
- `views.challenge.js` — challenge page and block page HTML
- `core.config.js` — constants, thresholds, event colors, required list keys

## Protection Scope

- `eu-api.ryzeon.wtf` → protects `/`
- `ryzeon.wtf/*` → protects all routes
- `*.ryzeon.wtf/*` → protects all routes

## Verification Flow

1. Suspicious or unverified request is served challenge page.
2. Browser collects fingerprint + behavior, fetches `/__challenge`.
3. Browser solves PoW and posts `/__verify`.
4. Worker validates challenge state/signature/replay constraints.
5. On success, signed cookies are issued (`cf_shield`, `cf_shield_exp`, `cf_shield_sig`, `cf_fp`).

## API Endpoints

- `GET /__shield/stats`
- `POST /__shield/reload`
- `POST /__shield/blacklist/reload`
- `GET /__shield/blacklist`
- `PUT|POST /__shield/blacklist`
- `GET /__shield/lists`
- `PUT|POST /__shield/lists`

If `STATS_API_KEY` is configured, these endpoints require `Authorization: Bearer <key>`.

## Environment Variables

### Core Security

- `SHIELD_SECRET` (recommended)
- `IP_WHITELIST` (comma-separated)
- `IP_BLACKLIST` (comma-separated)
- `BLOCKED_COUNTRIES` (comma-separated ISO country codes)

### Webhooks

- `DISCORD_WEBHOOK_URL`
- `DISCORD_WEBHOOK_URL_2` (optional)
- `DISCORD_WEBHOOK_URL_SYSTEM` (optional, deploy/system notifications)
- `SHIELD_DASHBOARD_URL` (optional button)
- `SHIELD_EVENTS_URL` (optional button)
- `SHIELD_SERVICES_URL` (optional button)
- `SHIELD_PING_URL` (optional button)

### Version / Release Metadata

- `SHIELD_VERSION` (optional fallback)
- `SHIELD_RELEASE_BASE` (default `v4.0.0`)
- `SHIELD_RELEASE_BUMP` (`major|minor|patch`, default `patch`)

### External Logging

- `LOG_ENDPOINT`
- `LOG_API_KEY`

### Admin API

- `STATS_API_KEY`

## Cloudflare Bindings

Required at runtime:

- `SHIELD_KV` (KV namespace)
- `SHIELD_DB` (D1 database)
- `SHIELD_R2` (R2 bucket)
- `SHIELD_VERSION_METADATA` (Worker version metadata)

## Local Setup

```bash
npm install
npx wrangler login
```

## Remote/Headless Deploy (No Browser Login)

If your Worker runs on a remote machine, `wrangler login` may fail because OAuth callback expects `localhost:<port>` on the same device.

Use API token auth instead:

1. Create a Cloudflare API token with Worker deploy permissions.
2. Set environment variables on the machine:

```bash
export CLOUDFLARE_API_TOKEN="<your_token>"
export CLOUDFLARE_ACCOUNT_ID="<your_account_id>"
```

3. Deploy directly (no browser callback required):

```bash
npx wrangler deploy
```

For GitHub auto-deploy, add repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

This repo includes a workflow at `.github/workflows/deploy-worker.yml` that deploys on push to `main`.

Set secrets:

```bash
npx wrangler secret put SHIELD_SECRET
npx wrangler secret put DISCORD_WEBHOOK_URL
```

Deploy:

```bash
npx wrangler deploy
```

## Event Types (Discord / Logs)

Examples include:

- `PASSED`, `FAILED`, `CHALLENGED`, `EXPIRED`
- `BLOCKED`, `HARD_BLOCKED`, `RATE_LIMITED`
- `ATTACK`, `HONEYPOT`, `HONEYPOT_FORM`
- `BOT_DETECTED`, `BOT_FARM`, `AI_CRAWLER`, `COUNTRY_BLOCKED`, `VPN_BLOCKED`
- `SYSTEM_UPDATE`, `DEPLOYED`, `ERROR`

## Notes

- Score shown in webhook cards is threat-oriented and now includes IP reputation influence.
- `SYSTEM_UPDATE` webhooks are routed to system webhook target and deduped per deployed version.
- Verify `PASSED/FAILED` webhooks are delayed briefly and deduped to reduce notification spam.

## License

This project is private/internal unless you explicitly add a license file.
