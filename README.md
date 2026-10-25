# TrustVault

TrustVault is a security-focused document-sharing platform with PostgreSQL least-privilege roles, server-side sessions, centralized authorization, encrypted storage, permission-filtered search, organizational folders, document versions, admin audit/anomaly views, metadata-only AI suggestions, and a React/Vite client. Uploads fail closed unless a malware scanner is explicitly configured. The included EC2 setup is a demonstration deployment; it does not replace a production ingress, malware scanner, or independent audit anchor.

Full project documentation: [docs/PROJECT_DOCUMENTATION.md](docs/PROJECT_DOCUMENTATION.md)

## Architecture

- Node.js 20, TypeScript, Fastify, PostgreSQL, React and Vite.
- The Fastify API authenticates opaque server-side sessions and routes every access through a registered authorization action. The app refuses startup if a route does not declare a known action.
- PostgreSQL's `trustvault_authorize(actor, document, action)` function is the policy source used by the TypeScript `authorize()` entry point and by permission-filtered SQL list/search queries.
- The migrations create separate migrator and application roles. The application role has only the DML needed by current routes; it cannot update or delete audit rows.
- Files are kept in a private storage directory, never served statically. The React client accesses files only through authenticated API endpoints.

The requested Fastify 4 version was not retained: npm audit identified an authentication-bypass advisory affecting that line with no patched 4.x release available at implementation time. The project uses Fastify 5 instead. This is a deliberate compatibility tradeoff.

## Authorization model

Folders are organization-wide organizational metadata only and confer no access. Folder management is owner-role restricted; folder visibility never substitutes for a document grant. Every document read, list/search result, version list/download/create, grant operation, and document mutation is checked on the server. Search applies live authorization inside a SQL join before returning rows and has no count/facet endpoints. Name, owner, category, and date filters are applied in that same query. Soft-deleted documents are excluded unless the caller explicitly asks for deleted results and has restore permission. An admin may manage user accounts and view audit activity, but has no implicit document-content or metadata access.

| Role | Document create | Own document | Other document | User administration |
|---|---|---|---|---|
| `admin` | No | Only if explicitly granted | Only if explicitly granted | Yes |
| `owner` | Yes | Implicit `manage` | Only if explicitly granted | No |
| `viewer` | No | Only if explicitly granted | Only if explicitly granted | No |

| Grant level | Read metadata, list, download | Rename/category/version | Grant/revoke, delete, restore |
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

Scanning is fail-closed by default: when `MALWARE_SCANNER` is unset or names an unsupported provider, valid uploads return `503 Uploads temporarily unavailable` and the denied attempt is audited. Set `MALWARE_SCANNER=local-basic` to opt into the built-in demo-grade scanner. It rejects the EICAR test string, MZ/ELF/Mach-O executable headers, and selected script/macro markers; it is heuristic and is **not a malware-detection product or a replacement for ClamAV**. It cannot reliably identify unknown, obfuscated, or encoded threats. Use an integrated ClamAV provider for production; do not treat `local-basic` as production protection. Unsupported provider names are reported at startup and leave uploads unavailable rather than bypassing scanning. `createApp()` also accepts a pluggable `malwareScanner` callback for tests and provider integrations. Seeded demo files are trusted fixtures and are marked clean.

Downloads decrypt files of at most 10 MiB into memory before streaming. This bounds memory use but is not a large-file streaming design.

## Audit trail and its limits

Every registered request is audited in the same transaction as its action. Authorization denials, CSRF/schema rejections, unmatched routes, malformed requests, and handler failures are also recorded; inability to write the audit event fails closed. Rows include actor/role, IP, user agent, document, action, outcome, reason, and request ID. `prev_hash` plus HMAC-SHA256 `row_hash` values form a chain. Database triggers reject `UPDATE`, `DELETE`, and `TRUNCATE`; the app role has only `SELECT` and `INSERT` on `audit_log`.

Run `npm run verify-chain` to verify the chain with `AUDIT_HMAC_SECRET`. Admins can also view recent activity, verify the chain, and see aggregate flags for repeated denials, bulk downloads, grant bursts, off-hours document activity, and failed chain verification. Audit events never expose a document title or identifier to an admin unless that admin separately has document metadata permission. This protects against alteration by a database-only attacker who lacks the HMAC key. It does **not** protect against a database superuser who also obtains the HMAC key, nor does it provide non-repudiation or external durability. Production should export/anchor chain heads outside the database.

## Search, folders, versions, and AI suggestions

`GET /api/documents` and `GET /api/search` accept `q`, `name`, `owner`, `category`, `from`, and `to`; only authorized rows are returned. There are intentionally no totals or facets that could reveal inaccessible documents. Folder listing is organizational and does not imply access; document routes continue to check the document grant. Versions inherit the parent document's live permission: metadata and download are checked through the parent, and creating a version requires edit or manage. Soft-deleted items remain protected and are only discoverable to callers with restore permission.

`POST /api/documents/:id/ai-suggestions` sends document metadata (title, description, category, owner display name), never file content, to an optional injected provider. The default is deterministic and needs no API key. Provider output is schema-checked and restricted to currently active eligible users. Suggestions cannot create grants. The owner records a separate accepted/rejected/modified decision at `/api/documents/:id/ai-suggestions/:suggestionId/decision`; any resulting access change must still be made through the ordinary grant route. Metadata is untrusted input and providers must not treat it as instructions.

The web interface provides authorized search/filtering, upload, metadata/version editing, soft delete/restore for managers, share/revoke, organizational folders, and admin audit/anomaly views. The Vite development server proxies `/api` to the API locally; production serves the built UI from the API process.

## What I chose not to build, and why

- No production-grade malware engine is bundled. `local-basic` is a demo-grade heuristic only; with no recognized scanner, uploads remain unavailable rather than being accepted.
- Archives and preview rendering are not supported. This avoids archive extraction/ZIP-bomb exposure and prevents active document content from being rendered inline.
- Groups do not grant document access; adding group-derived authorization would change revocation and permission semantics.
- No hosted AI provider, API key, or automatic grant application is configured. Provider use must be explicitly wired, and all suggestions remain owner-reviewed and non-authoritative.
- There is no external audit anchor. A database superuser holding the HMAC key can forge a chain; production operators must independently anchor/export audit heads.
- The EC2 convenience deployment uses a public Cloudflare quick tunnel whose URL changes on restart. It has no edge authentication or stable hostname and is not production ingress. For production, use managed TLS ingress and access controls.
- Demo account names and the local default password are public. Production seeding requires an explicit `SEED_DEMO_PASSWORD`; change or disable demo accounts before storing sensitive documents.
- There is no built-in ClamAV/hosted scanner integration. `local-basic` is demonstrative and must not be relied on for production malware detection.
- The API session cookie remains `Secure`; do not weaken it to support plain-HTTP production. Put production traffic behind HTTPS.

## Revocation and in-flight requests

Every request reads the current session and grant state; there is no cross-request authorization cache. Revocation serializes against downloads using document-scoped PostgreSQL advisory locks. If a download acquired its lock first, the revoke waits until that response finishes; bytes already sent cannot be recalled. After the revoke commits, later requests and unused tokens are denied. This provides immediate revocation for new accesses at the cost of a database check/lock per operation and potential revoke latency while a download is in flight.

## Environment variables

| Name | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes | Application-role PostgreSQL connection |
| `DB_MIGRATION_URL` | Yes for the Docker startup migration | Restricted migrator-role connection; do not reuse the app role |
| `MASTER_KEY` | Yes | Wraps per-file data keys |
| `AUDIT_HMAC_SECRET` | Yes | HMAC key for audit-chain rows |
| `SESSION_SECRET` | Yes | Signs CSRF tokens |
| `PORT` | No; default `3000` | API listen port |
| `STORAGE_DIRECTORY` | No; default `storage` | Private encrypted-file directory; use persistent private storage |
| `MALWARE_SCANNER` | No; unset or unknown rejects uploads | Set to `local-basic` for demo-grade scanning; use ClamAV for production |
| `NODE_ENV` | No; Docker sets `production` | Runtime mode; production seeding requires `SEED_DEMO_PASSWORD` |
| `POSTGRES_MIGRATOR_PASSWORD` | Docker Compose only | PostgreSQL migrator role password |
| `POSTGRES_APP_PASSWORD` | Docker Compose only | PostgreSQL application role password |
| `SEED_DEMO_PASSWORD` | Required only for production seed | Password hashed for the seeded demo users; local seed defaults to the public demo password if unset |

`MASTER_KEY`, `AUDIT_HMAC_SECRET`, and `SESSION_SECRET` must each be at least 32 UTF-8 bytes. Startup validates all required API variables together and prints invalid variable names, never values. Keep `.env` out of Git and use distinct randomly generated values for every environment.

`MALWARE_SCANNER` supports only the explicit `local-basic` provider in this build. Leaving it unset or setting an unknown provider keeps uploads fail-closed, including in production. The demo scanner checks a short list of raw byte/text markers and is not a substitute for ClamAV; integrating a production provider requires wiring its scanner callback. `SEED_DEMO_PASSWORD` has no production fallback: set a unique password before running `NODE_ENV=production npm run seed`. Never use the local demo password for a public deployment.

## Local development on Windows

Use Node.js 20 as specified by `package.json`. Compose uses PostgreSQL 16 on Debian Bookworm. Node 24 is outside the supported `>=20 <21` engine range and npm reports an engine warning when it is used.

1. Copy `.env.example` to `.env`; replace every placeholder with unique secrets and configure both database URLs. For Compose, use host port `5432` in the URLs; Compose binds PostgreSQL to `127.0.0.1` only. Set `MALWARE_SCANNER=local-basic` for demo uploads; keep it unset to reject uploads.
2. Start the database, migrate, seed, and launch the API and UI with the one-command local setup:

   ```powershell
   npm run start:local
   ```

   The script ensures `D:\` is on `PATH`, checks Docker, starts only the Compose database, waits for port 5432, runs the idempotent migration and seed commands, starts API/UI terminals if they are not already healthy, and prints the URLs and demo accounts. Install dependencies separately with `npm ci` if `node_modules` is not present.

   API health is available at `http://127.0.0.1:3000/healthz`. The UI is at `http://127.0.0.1:5173` and proxies `/api` to the API by default. Set `TRUSTVAULT_API_TARGET` if the API is at another origin. Docker Compose is used only for the database by `start:local`; the API and UI run through npm.

## Deployment

Build and run the runtime image with Docker or a compatible container platform. The image contains no `.env` file, credentials, or secret build arguments. At each container start it runs `npm run db:migrate` using `DB_MIGRATION_URL` before starting the API. The migrations are idempotently tracked in `schema_migrations`; the API connection remains the separate `DATABASE_URL` app role. Configure a persistent private volume for `STORAGE_DIRECTORY`, restrict access to it, and put the API behind HTTPS/TLS termination before production use. The API reads `PORT` from the environment (default `3000`). Compose runs a one-shot migration service before the API as an additional dependency; the API startup migration is a final consistency check.

Required host variable names: `DATABASE_URL`, `DB_MIGRATION_URL`, `MASTER_KEY`, `AUDIT_HMAC_SECRET`, `SESSION_SECRET`. Also set `PORT` when the host does not use 3000 and `STORAGE_DIRECTORY` when persistent storage is mounted elsewhere. For the provided Compose database, additionally configure `POSTGRES_MIGRATOR_PASSWORD` and `POSTGRES_APP_PASSWORD`. Supply values through the host's secret manager; do not place them in Dockerfile instructions, image layers, source control, or deployment logs. Use unique independent 32-byte-minimum secrets and separate database roles.

The deployed API fails closed on upload when `MALWARE_SCANNER` is unset. Do not use `local-basic` as production protection; integrate ClamAV or another production-grade scanner provider before accepting production uploads. The smoke script can test a pre-seeded document without upload, or test an actual upload when `TRUSTVAULT_SMOKE_FILE` is provided after a production scanner is integrated.

To smoke-test an HTTPS deployment, set the smoke-only environment values `TRUSTVAULT_BASE_URL`, `TRUSTVAULT_OWNER_EMAIL`, `TRUSTVAULT_OWNER_PASSWORD`, `TRUSTVAULT_VIEWER_EMAIL`, `TRUSTVAULT_VIEWER_PASSWORD`, `TRUSTVAULT_ADMIN_EMAIL`, and `TRUSTVAULT_ADMIN_PASSWORD`, then run:

```powershell
npm ci
npm run smoke-test
```

The script discovers the owner's first accessible document if `TRUSTVAULT_DOCUMENT_ID` is omitted. To include an upload, also set `TRUSTVAULT_SMOKE_FILE` to a valid PDF after a production-grade scanner provider has been integrated. Smoke-test credentials are script inputs, not application host settings; keep them out of logs and remove them after use.

## Deploy on EC2 (Amazon Linux 2023)

This single-process setup serves the built React application and API from port 3000. From an Amazon Linux 2023 EC2 instance, allow **SSH from your IP only** in the security group; do not open any other inbound ports. The app is reachable through a Cloudflare quick tunnel, not a directly exposed EC2 port.

```bash
cd ~
git clone https://github.com/RamGopalImadabathini/trustvault.git
cd ~/trustvault
bash deploy/ec2/setup.sh
bash deploy/ec2/show-link.sh
```

The setup installs Node 20 with nvm, Docker and its Compose CLI plugin, prompts without echo for a 12+ character URL-safe production seed password, generates a private `.env` only when one does not already exist, starts PostgreSQL, builds the application, migrates and seeds the database, then enables the app and tunnel systemd services. The generated `.env` is never printed or replaced by setup. If an existing `.env` has no `SEED_DEMO_PASSWORD`, add it securely before rerunning setup; setup never overwrites that file. The database and application data persist in Docker volumes and the repository's private `storage/` directory.

To update an existing checkout:

```bash
cd ~/trustvault
git pull origin main
npm ci
npm run build:all
npm run db:migrate
sudo systemctl restart trustvault
bash deploy/ec2/show-link.sh
```

The quick-tunnel URL is **public and unauthenticated at the network edge**: anyone who obtains the link can reach the app's public login and health endpoints, though protected application routes still require app authorization. The free quick-tunnel link changes whenever the tunnel process restarts; rerun `show-link.sh` to retrieve the latest link. This is a demo/convenience deployment, not a stable production ingress.

The local seed defaults to the public demo password `TrustVault-Local-Demo-2026!`. Production seed requires `SEED_DEMO_PASSWORD` and never falls back to that value. For EC2 setup, enter a unique URL-safe password when prompted; setup stores it in the private `.env` without echoing it. Change or remove seeded demo accounts before exposing sensitive data. `local-basic` is a demo-grade heuristic scanner, not production malware protection. Production uploads require ClamAV or another hosted/production-grade scanner integration; otherwise uploads remain disabled.

The seed command creates one admin, two owners, and three viewers. In local development, all six use the **demo-only** default password `TrustVault-Local-Demo-2026!` unless `SEED_DEMO_PASSWORD` is set:

| Role | Email |
|---|---|
| admin | `admin@trustvault.local` |
| owner | `owner.one@trustvault.local` |
| owner | `owner.two@trustvault.local` |
| viewer | `viewer.one@trustvault.local` |
| viewer | `viewer.two@trustvault.local` |
| viewer | `viewer.three@trustvault.local` |

The local demo password is public and must never be used outside a local demonstration. Production seeding refuses to run unless `SEED_DEMO_PASSWORD` is configured.

### PowerShell API walkthrough

The cookie is marked `Secure`, as required. For local plain-HTTP API calls, the following example forwards the cookie explicitly rather than relying on a browser's cookie policy. It uses an existing seeded document. **A new upload returns 503 when `MALWARE_SCANNER` is unset.** Do not bypass the scanner to make an upload appear successful.

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
curl.exe -sS -o $ownerDocsPath "$base/api/search?q=Demo%20document%3A%20owner%20one" `
  -H "Cookie: $ownerCookie"
$documentId = (Get-Content -Raw $ownerDocsPath | ConvertFrom-Json).results[0].id

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

# New uploads intentionally fail closed when MALWARE_SCANNER is unset.
$pdf = Join-Path $temp "sample.pdf"
Set-Content -Path $pdf -Value "%PDF-1.7 demo" -NoNewline -Encoding ascii
$uploadStatus = curl.exe -sS -o (Join-Path $temp "upload.json") -w "%{http_code}" `
  -X POST "$base/api/documents" -H "Cookie: $ownerCookie" `
  -H "X-CSRF-Token: $($ownerMe.csrfToken)" `
  -F "title=Sample" -F "file=@$pdf;type=application/pdf"
Write-Output "Upload without scanner=$uploadStatus (expected 503)"
Remove-Item -LiteralPath $temp -Recurse -Force
```

For an end-to-end *new upload* flow, set `MALWARE_SCANNER=local-basic` for a local demo, or wire and test a production-grade scanner callback before deployment. Integration tests use a test-only scanner callback and exercise upload, grant, download, token replay/sharing, revocation, and the cross-user denial matrix.

## Tests and checks

Run the complete checks:

```powershell
npm run typecheck
npm run lint
npm test
npm run build:all
npm audit
npm run mutation-check
npm run verify-chain
```

The PostgreSQL integration suite runs when `DATABASE_URL` is configured and `TRUSTVAULT_INTEGRATION` is not `false`; it also requires `DB_MIGRATION_URL` for isolated fixture cleanup. It was run against the local PostgreSQL 18 cluster in this workspace.

### Mutation-check results

Last run: 12 mutations; all were killed by at least one failing test. Each mutation runs the complete test suite. The runner restores each file in a `finally` block and exits nonzero for any survivor, adapter error, or test-run error.

| Mutation | Result | Failing test(s) |
|---|---|---|
| Allow UPDATE on users through app DB role | KILLED | `phase 1 security foundation restricts the application DB role to least-privilege reads and inserts` |
| Disable audit UPDATE protection | KILLED | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` |
| Disable audit TRUNCATE protection | KILLED | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` |
| Accept undersized secrets | KILLED | `loadConfig measures secrets in UTF-8 bytes`; `loadConfig does not include secret values in configuration errors` |
| Accept non-PostgreSQL database URLs | KILLED | `loadConfig rejects unsupported or malformed database URLs` (three invalid URL cases) |
| Bypass document `authorize()` call site | KILLED | `enforces cross-user access, download, audit, and immediate revocation`; `keeps search, folders, versions, AI decisions, and admin metadata scoped`; `denies an ungranted caller on every document-content and permission route`; `revokes sessions after a role change or deactivation` |
| Bypass framework failure `authorize()` call site | KILLED | `keeps search, folders, versions, AI decisions, and admin metadata scoped`; `denies an ungranted caller on every document-content and permission route`; `audits unmatched routes and malformed requests` |
| Allow uploads without a malware scanner | KILLED | `enforces cross-user access, download, audit, and immediate revocation` |
| Disable route-registry authorization guard | KILLED | `route authorization registry refuses to start with a missing or unknown route action` |
| Disable `audit_log` insert | KILLED | `health endpoint fails closed when the audit write cannot be persisted`; `audit chain serializes append and writes denied events with chained hashes`; integration test `enforces cross-user access, download, audit, and immediate revocation` |
| Remove active-document SQL permission filter | KILLED | `enforces cross-user access, download, audit, and immediate revocation`; `keeps search, folders, versions, AI decisions, and admin metadata scoped`; `denies an ungranted caller on every document-content and permission route` |
| Remove deleted-document restore permission filter | KILLED | `keeps search, folders, versions, AI decisions, and admin metadata scoped`; `denies an ungranted caller on every document-content and permission route`; `revokes sessions after a role change or deactivation` |

## What I chose not to build, and why

- Folder inheritance and group-derived grants: folders and groups are organizational only; adding indirect authorization would expand the permission and revocation surface.
- Preview rendering, archive extraction, and export endpoints: files are downloaded only as attachments; archives are rejected to avoid ZIP-bomb/extraction exposure.
- A production malware-scanning engine or hosted AI provider: `local-basic` is demo-grade only; uploads fail closed unless a provider is explicitly selected, and AI uses the deterministic fallback unless explicitly configured.
- External audit anchoring: a database superuser with the HMAC key remains able to forge the chain, so production needs an independent anchor and deployment review.
