# TrustVault

TrustVault is a security-focused document-sharing API. Phases 1–3 and 5 are implemented: PostgreSQL schema and least-privilege roles, server-side sessions, centralized authorization and a startup route registry, and a tamper-evident audit chain. Phase 4 has encrypted storage, upload validation, and authorized downloads, but fails uploads closed until a real malware scanner is wired. The React/Vite client, folders, version creation, audit UI, AI suggestions, external audit anchoring, and deployment to a live host are not implemented.

## Architecture

- Node.js 20, TypeScript, Fastify, PostgreSQL, React and Vite.
- The Fastify API authenticates opaque server-side sessions and routes every access through a registered authorization action.
- PostgreSQL's `trustvault_authorize(actor, document, action)` function is the policy source used by the TypeScript `authorize()` entry point and by permission-filtered SQL list/search queries.
- The migrations create separate migrator and application roles. The application role has only the DML needed by current routes; it cannot update or delete audit rows.
- Files are kept in a private storage directory, never served statically. The browser client is only a scaffold; it does not access storage.

The requested Fastify 4 version was not retained: npm audit identified an authentication-bypass advisory affecting that line with no patched 4.x release available at implementation time. The project uses Fastify 5 instead. This is a deliberate compatibility tradeoff.

## Authorization model

Folders are organizational metadata only and confer no access. Every document read, list/search result, version list, download, grant operation, and document mutation is checked on the server. Search filters permissions inside the SQL query. An admin may manage user accounts but has no implicit document-content or document-metadata access.

| Role | Document create | Own document | Other document | User administration |
|---|---|---|---|---|
| `admin` | No | Only if explicitly granted | Only if explicitly granted | Yes |
| `owner` | Yes | Implicit `manage` | Only if explicitly granted | No |
| `viewer` | No | Only if explicitly granted | Only if explicitly granted | No |

| Grant level | Read metadata, list, download | Edit metadata | Grant/revoke, delete, restore |
|---|---:|---:|---:|
| `read` | Yes | No | No |
| `edit` | Yes | Yes | No |
| `manage` | Yes | Yes | Yes |

Grants can expire and are checked live on every request. A route without a valid authorization action prevents app startup. Denied document reads use the same `404 {"error":"Not found"}` response as missing documents. Search/list output contains only authorized documents, so inaccessible documents do not affect returned counts or facets (there are no facets/count endpoints). Response content is equivalent, but database work and network scheduling are not constant-time; see the knowingly accepted limitations in `THREATS.md`.

## Authentication and sessions

Passwords are hashed with Argon2id. Login uses uniform failure text, a dummy hash for unknown accounts, rate limiting, and lockout after repeated failures. Sessions are random, server-side, revocable, and expire after eight hours. The cookie is `HttpOnly; Secure; SameSite=Strict`; state-changing authenticated requests require a session-bound CSRF token. User role changes and deactivation revoke all that user's sessions. JWTs are not used. Public login error content/status are uniform, but exact network timing is not guaranteed.

## Storage and uploads

Each accepted file gets a random storage key and a per-file AES-256-GCM data key. The data key is AES-GCM-wrapped using a key derived from `MASTER_KEY`; SHA-256 is checked after decryption. Download endpoints re-check authorization and stream only after the audit write commits. Download tokens are hashed at rest, short-lived, single-use, and bound to both user and document. A PostgreSQL advisory lock serializes a download with revocation.

Uploads are limited to 10 MiB and an allowlist of PDF, PNG, JPEG, and UTF-8 text; extension, declared MIME, and magic bytes must match. Filenames are normalized and stripped of path components/control characters. Archives are not accepted, so the implementation does not extract archives or process ZIP bombs. Downloads set attachment disposition and `X-Content-Type-Options: nosniff`.

**Malware scanning is fail-closed but not yet wired to a provider.** `createApp()` accepts a pluggable `malwareScanner` callback; without one, valid uploads return `503 Uploads temporarily unavailable` and are audited. The integration tests inject a test scanner that returns `clean`; this is not an antivirus product. Connect a real scanner before enabling uploads in a deployment. Seeded demo files are trusted fixtures and are marked clean.

Downloads decrypt files of at most 10 MiB into memory before streaming. This bounds memory use but is not a large-file streaming design.

## Audit trail and its limits

Every registered request is audited in the same transaction as its action. Authorization denials, CSRF/schema rejections, unmatched routes, malformed requests, and handler failures are also recorded; inability to write the audit event fails closed. Rows include actor/role, IP, user agent, document, action, outcome, reason, and request ID. `prev_hash` plus HMAC-SHA256 `row_hash` values form a chain. Database triggers reject `UPDATE`, `DELETE`, and `TRUNCATE`; the app role has only `SELECT` and `INSERT` on `audit_log`.

Run `npm run verify-chain` to verify the chain with `AUDIT_HMAC_SECRET`. This protects against alteration by a database-only attacker who lacks the HMAC key. It does **not** protect against a database superuser who also obtains the HMAC key, nor does it provide non-repudiation or external durability. Production should export/anchor chain heads outside the database. No audit-view UI exists yet.

## Revocation and in-flight requests

Every request reads the current session and grant state; there is no cross-request authorization cache. Revocation serializes against downloads using document-scoped PostgreSQL advisory locks. If a download acquired its lock first, the revoke waits until that response finishes; bytes already sent cannot be recalled. After the revoke commits, later requests and unused tokens are denied. This provides immediate revocation for new accesses at the cost of a database check/lock per operation and potential revoke latency while a download is in flight.

## Environment variables

| Name | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes for API | Application-role PostgreSQL connection |
| `DB_MIGRATION_URL` | Yes for migrations | Migrator-role connection |
| `MASTER_KEY` | Yes | Wraps per-file data keys |
| `AUDIT_HMAC_SECRET` | Yes | HMAC key for audit-chain rows |
| `SESSION_SECRET` | Yes | Signs CSRF tokens |
| `POSTGRES_MIGRATOR_PASSWORD` | Docker Compose | PostgreSQL migrator role password |
| `POSTGRES_APP_PASSWORD` | Docker Compose | PostgreSQL application role password |
| `PORT` | No; default `3000` | API listen port |
| `STORAGE_DIRECTORY` | No; default `storage` | Private encrypted-file directory |
| `NODE_ENV` | No | Runtime mode; demo seeding refuses production by default |
| `ALLOW_DEMO_SEED` | No | Must be `true` to override the production seed refusal; do not use in production |

`MASTER_KEY`, `AUDIT_HMAC_SECRET`, and `SESSION_SECRET` must each be at least 32 UTF-8 bytes. Startup validates all required API variables together and prints invalid variable names, never values. Keep `.env` out of Git and use distinct randomly generated values for every environment.

## Local development on Windows

Use Node.js 20 as specified by `package.json`. PostgreSQL 16 is the Compose target. This repository was exercised in the current environment against an isolated PostgreSQL 18 instance because Docker was unavailable; the host also had Node 24, so the `>=20 <21` engine target was not directly validated here.

1. Copy `.env.example` to `.env`; replace every placeholder with unique secrets and configure both database URLs. For Compose, use host port `5432` in the URLs; Compose binds PostgreSQL to `127.0.0.1` only.
2. Start the database, install dependencies, migrate, and seed:

   ```powershell
   docker compose --profile local up -d db
   npm ci
   npm run db:migrate
   npm run seed
   ```

3. Start the API and check health:

   ```powershell
   npm run dev
   Invoke-RestMethod http://127.0.0.1:3000/healthz
   ```

   `npm run dev:web` starts the Vite development server separately. To run the Compose stack, use `docker compose --profile local up -d --build`; run the demo seed service with `docker compose --profile local run --rm seed`.

The seed command creates one admin, two owners, and three viewers. All six use the **demo-only** password `TrustVault-Local-Demo-2026!`:

| Role | Email |
|---|---|
| admin | `admin@trustvault.local` |
| owner | `owner.one@trustvault.local` |
| owner | `owner.two@trustvault.local` |
| viewer | `viewer.one@trustvault.local` |
| viewer | `viewer.two@trustvault.local` |
| viewer | `viewer.three@trustvault.local` |

The demo password is public and must never be used outside a local demonstration. Demo seed is refused when `NODE_ENV=production` unless explicitly overridden.

### PowerShell API walkthrough

The cookie is marked `Secure`, as required. For local plain-HTTP API calls, the following example forwards the cookie explicitly rather than relying on a browser's cookie policy. It uses an existing seeded document. **A new upload returns 503 until a real malware-scanner callback is wired into the API.** Do not bypass the scanner to make an upload appear successful.

```powershell
$base = "http://127.0.0.1:3000"
$password = "TrustVault-Local-Demo-2026!"
$temp = Join-Path $env:TEMP "trustvault-walkthrough"
New-Item -ItemType Directory -Path $temp -Force | Out-Null

$ownerLogin = Invoke-WebRequest -Method Post -Uri "$base/api/auth/login" `
  -ContentType "application/json" `
  -Body (@{ email = "owner.one@trustvault.local"; password = $password } | ConvertTo-Json)
$ownerCookie = ([string]$ownerLogin.Headers["Set-Cookie"] -split ";")[0]
$ownerMePath = Join-Path $temp "owner-me.json"
curl.exe -sS -o $ownerMePath "$base/api/auth/me" -H "Cookie: $ownerCookie"
$ownerMe = Get-Content -Raw $ownerMePath | ConvertFrom-Json
$ownerDocsPath = Join-Path $temp "owner-docs.json"
curl.exe -sS -o $ownerDocsPath "$base/api/documents?q=Demo%20document%3A%20owner%20one" `
  -H "Cookie: $ownerCookie"
$documentId = (Get-Content -Raw $ownerDocsPath | ConvertFrom-Json).documents[0].id

$viewerLogin = Invoke-WebRequest -Method Post -Uri "$base/api/auth/login" `
  -ContentType "application/json" `
  -Body (@{ email = "viewer.three@trustvault.local"; password = $password } | ConvertTo-Json)
$viewerCookie = ([string]$viewerLogin.Headers["Set-Cookie"] -split ";")[0]
$viewerMePath = Join-Path $temp "viewer-me.json"
curl.exe -sS -o $viewerMePath "$base/api/auth/me" -H "Cookie: $viewerCookie"
$viewerMe = Get-Content -Raw $viewerMePath | ConvertFrom-Json

$grantJson = Join-Path $temp "grant.json"
$grantBody = ConvertTo-Json -InputObject ([ordered]@{ userId = [string]$viewerMe.id; level = "read" }) -Compress
[System.IO.File]::WriteAllText($grantJson, $grantBody, [System.Text.UTF8Encoding]::new($false))
$grantStatus = curl.exe -sS -o (Join-Path $temp "grant-response.json") -w "%{http_code}" `
  -X POST "$base/api/documents/$documentId/grants" `
  -H "Cookie: $ownerCookie" -H "X-CSRF-Token: $($ownerMe.csrfToken)" `
  -H "Content-Type: application/json" --data-binary "@$grantJson"
$token1Status = curl.exe -sS -o (Join-Path $temp "token1.json") -w "%{http_code}" `
  -X POST "$base/api/documents/$documentId/download-tokens" `
  -H "Cookie: $viewerCookie" -H "X-CSRF-Token: $($viewerMe.csrfToken)"
$token2Status = curl.exe -sS -o (Join-Path $temp "token2.json") -w "%{http_code}" `
  -X POST "$base/api/documents/$documentId/download-tokens" `
  -H "Cookie: $viewerCookie" -H "X-CSRF-Token: $($viewerMe.csrfToken)"
$token1 = (Get-Content -Raw (Join-Path $temp "token1.json") | ConvertFrom-Json).token
$token2 = (Get-Content -Raw (Join-Path $temp "token2.json") | ConvertFrom-Json).token
$downloadStatus = curl.exe -sS -o (Join-Path $temp "download.bin") -w "%{http_code}" `
  "$base/api/downloads/$token1" -H "Cookie: $viewerCookie"
$revokeStatus = curl.exe -sS -o (Join-Path $temp "revoke.json") -w "%{http_code}" `
  -X DELETE "$base/api/documents/$documentId/grants/$($viewerMe.id)" `
  -H "Cookie: $ownerCookie" -H "X-CSRF-Token: $($ownerMe.csrfToken)"
$afterRevokeStatus = curl.exe -sS -o (Join-Path $temp "after-revoke.json") -w "%{http_code}" `
  "$base/api/downloads/$token2" -H "Cookie: $viewerCookie"

# Expected: Grant=201, TokenIssue=201/201, Download=200,
# Revoke=200, DownloadAfterRevoke=404.
Write-Output "Grant=$grantStatus; TokenIssue=$token1Status/$token2Status; Download=$downloadStatus; Revoke=$revokeStatus; DownloadAfterRevoke=$afterRevokeStatus"

# New uploads intentionally fail closed without a scanner provider.
$pdf = Join-Path $temp "sample.pdf"
Set-Content -Path $pdf -Value "%PDF-1.7 demo" -NoNewline -Encoding ascii
$uploadStatus = curl.exe -sS -o (Join-Path $temp "upload.json") -w "%{http_code}" `
  -X POST "$base/api/documents" -H "Cookie: $ownerCookie" `
  -H "X-CSRF-Token: $($ownerMe.csrfToken)" `
  -F "title=Sample" -F "file=@$pdf;type=application/pdf"
Write-Output "Upload without scanner=$uploadStatus (expected 503)"
Remove-Item -LiteralPath $temp -Recurse -Force
```

For an end-to-end *new upload* flow, configure a real `malwareScanner` provider in the application composition and test that provider before deployment. Integration tests use a test-only scanner callback and exercise upload, grant, download, token replay/sharing, revocation, and the cross-user denial matrix.

## Tests and checks

Run the complete checks:

```powershell
npm run typecheck
npm run lint
npm test
npm run build
npm audit
npm run mutation-check
npm run verify-chain
```

The PostgreSQL integration suite runs when `DATABASE_URL` is configured and `TRUSTVAULT_INTEGRATION` is not `false`; it also requires `DB_MIGRATION_URL` for isolated fixture cleanup. It was run against the local PostgreSQL 18 cluster in this workspace.

### Mutation-check results

Last run: 11 mutations; all were killed by at least one failing test. The mutation runner restores each file in a `finally` block and exits nonzero for any survivor, adapter error, or test-run error.

| Mutation | Result | Failing test(s) |
|---|---|---|
| Allow UPDATE on users through app DB role | KILLED | `phase 1 security foundation restricts the application DB role to least-privilege reads and inserts` |
| Disable audit UPDATE protection | KILLED | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` |
| Disable audit TRUNCATE protection | KILLED | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` |
| Accept undersized secrets | KILLED | `loadConfig measures secrets in UTF-8 bytes`; `loadConfig does not include secret values in configuration errors` |
| Accept non-PostgreSQL database URLs | KILLED | `loadConfig rejects unsupported or malformed database URLs` (three invalid URL cases) |
| Bypass document `authorize()` call site | KILLED | `PostgreSQL authorization and revocation integration enforces cross-user access, download, audit, and immediate revocation` |
| Bypass framework failure `authorize()` call site | KILLED | `PostgreSQL authorization and revocation integration audits unmatched routes and malformed requests` |
| Disable route-registry authorization guard | KILLED | `route authorization registry refuses to start with a missing or unknown route action` |
| Disable `audit_log` insert | KILLED | `health endpoint fails closed when the audit write cannot be persisted`; `audit chain serializes append and writes denied events with chained hashes`; integration test `enforces cross-user access, download, audit, and immediate revocation` |
| Remove document-list SQL grant filter | KILLED | `PostgreSQL authorization and revocation integration enforces cross-user access, download, audit, and immediate revocation` |
| Remove search SQL grant filter | KILLED | `PostgreSQL authorization and revocation integration enforces cross-user access, download, audit, and immediate revocation` |

## Deliberately not built yet

- Folder inheritance, groups, and bulk sharing: folders are organizational only; adding inheritance would expand the authorization surface.
- Document-version creation, previews, exports, admin audit UI, and AI suggestions: these need independent authorization/audit tests and are outside phases 1–5.
- A malware-scanning engine: no scanner is silently treated as successful; uploads fail closed until a provider is connected.
- External audit anchoring and a live production deployment: a database superuser with the HMAC key remains able to forge the chain, so production needs an external anchor.
