# TrustVault project documentation

## 1. Overview

TrustVault is a document-sharing application for an organization that needs to share files without turning account roles, a folder name, or a guessable URL into a document permission. It combines a React web client, a Fastify API, PostgreSQL policy checks, and encrypted private file storage. It is intended as a security-focused demonstration, not as a claim of production certification.

The project is designed around three non-negotiable rules:

1. **Grant-only access through every route.** A user may access another person's document only through an active, explicit document grant; there is no implicit access based on being an administrator, a folder member, or knowing an identifier.
2. **A provable, tamper-evident audit trail.** Document actions, including denials, are recorded in an append-only, HMAC-chained audit log in the action transaction.
3. **Immediate revocation.** Each access decision checks current grant/session state. Revocation takes effect on the next serialized authorization decision; bytes already delivered cannot be recalled.

The source of truth for implementation details is the application, database migrations, tests, deployment files, [README.md](../README.md), [PLAN.md](../PLAN.md), and [THREATS.md](../THREATS.md).

## 2. Project timeline

The table groups the reverse Git history into implementation phases. Hashes and dates below come from `git log --reverse --format="%h %ad %an %s" --date=short`; repeated hashes mean one commit contributed to more than one phase.

| Phase | Evidence from commits |
|---|---|
| Initial repository and scaffold | `781585d` (2026-10-19, initial README-only commit); `db4f8ad` (2026-10-21, phase 1 scaffold); `8ff5e32` (2026-10-22, database/config hardening) |
| Authentication and sessions | `035dbc7` (2026-10-22, audited authentication and encrypted document access); `e7fd95b` (2026-10-22, security regression coverage); `7832920` (2026-10-23, production seed-password requirement) |
| Authorization and grants | `035dbc7` (2026-10-22); `e7fd95b` (2026-10-22); `628fc85` (2026-10-23, complete authorized document-management UI) |
| Storage and uploads | `035dbc7` (2026-10-22); `6648cb4` (2026-10-22, local seed and private storage); `25d83dc` (2026-10-23, fail-closed local upload scanning) |
| Audit chain | `acc5198` (2026-10-22, search, audit, and AI phases); `c134c0f` (2026-10-22, security checks and deployment docs); `79751f3` (2026-10-23, access model and deployment risks) |
| Search, folders, and versions | `acc5198` (2026-10-22); `628fc85` (2026-10-23) |
| Admin view | `e5c694e` (2026-10-22, document and admin workspace); `628fc85` (2026-10-23) |
| AI suggestions | `acc5198` (2026-10-22); the user-facing workspace followed in `e5c694e` (2026-10-22) |
| Scanner | `25d83dc` (2026-10-23) |
| Deployment | `b0ee49d` (2026-10-22, migrations and smoke test); `dc89013` (2026-10-23, Render blueprint); `09e3aeb` (2026-10-23, serve built UI from API); `47d2464` and `6f5aed3` (2026-10-23, EC2 services/setup and documentation) |

The GitHub stub history was joined to the implementation history by `6b8f7c0` (2026-10-22, “merge initial GitHub stub history”). Later pull/branch merges are present in Git history as well. An earlier Express/JWT/bcrypt prototype was replaced by the implemented Fastify, database-backed session, and Argon2id design. The retained current source and commit log do not preserve enough of that discarded prototype to document its implementation or exact transition commit-by-commit.

## 3. Architecture

The browser treats all inputs as untrusted. The API resolves a server-side session, routes every request through an explicit authorization action, and uses parameterized SQL. PostgreSQL stores identity, grants, document metadata and versions, token state, and audit events. Encrypted file bytes are stored separately in a private directory and are not served as static assets. Optional AI suggestion providers receive document metadata only.

```mermaid
flowchart LR
    Browser[React browser<br/>untrusted inputs] -->|HTTPS in deployment / API requests| Edge[Ingress or demo quick tunnel]
    Edge --> API[Fastify API<br/>session, CSRF, schemas]
    API -->|authorize(actor, document, action)| DB[(PostgreSQL<br/>policy, grants, sessions)]
    API -->|same-transaction event| Audit[(Append-only audit_log<br/>HMAC hash chain)]
    API -->|ciphertext read/write| Storage[(Private file storage)]
    API -->|metadata only, optional| Provider[AI suggestion provider]
    Owner[Owner review] -->|separate decision request| API
```

**Upload flow:** the API authenticates and authorizes an owner, validates filename, extension, declared MIME, magic bytes, size, and text encoding, then requires a configured scanner to return clean. It creates a random per-file data key, encrypts the file, wraps the data key using a key derived from the master key, stores ciphertext privately, records version metadata, and writes the audit event in the database transaction. If no scanner is configured, uploads fail closed.

**Download flow:** an authenticated request is re-authorized against the current document grant and version. Where a short-lived download token is used, the token is hashed at rest, bound to its user/document/version, consumed once under a row lock, and checked against current authorization again. A document-scoped advisory lock serializes the download with revoke operations. The file is decrypted and integrity-checked before being streamed.

**Grant flow:** a document owner or manage-level grant holder requests a grant to an eligible active user. The API applies the normal authorization policy and escalation rules, writes the grant and audit event in one transaction, and the new grant is checked live on subsequent requests.

**Revoke flow:** the authorized actor revokes the active grant in a transaction. Document-scoped serialization prevents a concurrent download decision from passing the revoke and continuing as though the grant were active. The revoke event is audited before commit.

**Audit-write flow:** the API locks audit-chain appends, reads the previous row hash, canonicalizes the event, calculates HMAC-SHA256 with the audit secret, and inserts the chained row in the same database transaction as the associated request outcome. An audit-write failure aborts/fails closed rather than pretending the action was successfully recorded.

**Trust boundaries:** the browser and request metadata are untrusted; the public network/ingress is a transport boundary; the Fastify API and its secrets are trusted policy-enforcement components; PostgreSQL is a separate privilege boundary; the filesystem is private but is not itself an independent audit authority; and an optional AI provider is outside the application trust boundary and receives only selected metadata. A database superuser with the HMAC secret is outside the protections provided by the chain.

## 4. Tech stack and why

| Technology | Use and reason |
|---|---|
| Node.js 20 | Runtime selected by the package engine range (`>=20 <21`); supports the project's native `argon2` dependency. |
| TypeScript | Typed server/client source and compile-time checking across API and UI. |
| Fastify 5 | API routing, lifecycle hooks, multipart handling, cookies, security headers, and rate limiting. The project notes that it selected the patched Fastify 5 line over an unpatched Fastify 4 line when a reported authentication-bypass advisory had no fixed 4.x release. |
| PostgreSQL 16 | Relational integrity, transactional authorization/audit writes, migrations, least-privilege database roles, and policy SQL. |
| Argon2id | Password hashing designed to make offline password guessing more expensive. |
| AES-256-GCM and wrapped per-file keys | Authenticated encryption of stored files with a separately generated data key for each file. |
| React 18 and Vite 6 | Browser UI and development/production asset builds. |
| Docker Compose | Reproducible local PostgreSQL and application services; the database port binds to loopback for local access. |
| Vitest, Supertest, ESLint, TypeScript | Unit/integration tests, HTTP tests, static linting, type checking, and mutation checks. |
| Linux systemd, Docker Compose, Cloudflare `cloudflared` | Demonstration EC2 service startup and a temporary public tunnel; not a managed production ingress. |

## 5. Roles and permissions

| Role | Create documents | Own documents | Other users' documents | Administration |
|---|---|---|---|---|
| **Admin** | No | Only with an explicit grant | Only with an explicit grant | Manage user accounts and view audit/anomaly functions; no implicit document access |
| **Owner** | Yes | Implicit manage access | Only with an explicit grant | No user administration |
| **Viewer** | No | Only with an explicit grant | Only with an explicit grant | No |

| Grant level | Metadata/list/download | Edit metadata and create versions | Grant/revoke, delete, restore, view grants |
|---|---:|---:|---:|
| **read** | Yes | No | No |
| **edit** | Yes | Yes | No |
| **manage** | Yes | Yes | Yes |

Grant levels are document-scoped and checked live; grants may expire. Only a manage-authorized actor can delegate/manage access. A grantor cannot elevate a recipient beyond the grantor's effective rights; an edit-level grant is not sufficient to grant. Admin status does not elevate document access. Owners have implicit manage rights only for documents they own.

Folders are organizational metadata, not a permission container. They confer no access and there is deliberately **no folder inheritance**: moving a document, listing a folder, or being able to manage a folder must not silently change access to every document in it. Document access stays explicit and independently revocable.

## 6. Security design

- **One authorization policy:** API handlers call `authorize(actor, documentId, action)`, which invokes PostgreSQL's `trustvault_authorize` policy. SQL list/search queries use that same policy inside the query rather than retrieving unauthorized rows and filtering them afterward.
- **Route registry guard:** each registered API route must declare a known authorization action. The startup readiness hook rejects missing/unknown actions, including unmatched-route and request-error handlers.
- **Not-found privacy:** denied document requests and nonexistent document requests return the same `404` response body (`{"error":"Not found"}`). This is response equivalence, not a claim of constant-time execution.
- **Search privacy:** search/list queries apply the live permission predicate in SQL before returning rows. There are no totals/facets that reveal inaccessible documents.
- **Encrypted storage:** files are encrypted with AES-256-GCM using random per-file data keys; those keys are wrapped using a key derived from `MASTER_KEY`. Decryption verifies the authentication tag and SHA-256 digest. Storage is private and not statically exposed.
- **Download tokens:** bearer tokens are random, stored as hashes, bound to a user/document/version, expire after 60 seconds, are single-use under a database row lock, and undergo a fresh authorization check at redemption.
- **Upload checks:** files must be nonempty and at most 10 MiB, have an allowed PDF/PNG/JPEG/UTF-8 text extension and matching declared MIME/magic bytes, and pass filename normalization and text validation.
- **Fail-closed malware scanning:** no scanner or unsupported provider means uploads are unavailable (503), rather than unscanned files being accepted. `local-basic` recognizes the EICAR test string, executable headers, and selected script/macro markers only. It is explicitly demo-grade and can miss unknown, encoded, or obfuscated threats; it is not ClamAV or a production malware engine.
- **Passwords and sessions:** passwords use Argon2id. Sessions are opaque, random, stored server-side, revocable, and expire after eight hours. Session lookup checks current user activity and revocation. Role changes/deactivation revoke current sessions.
- **Cookies and CSRF:** the `tv_session` cookie is `HttpOnly; Secure; SameSite=Strict`, path `/`, with an eight-hour max age. Authenticated state-changing requests require a session-bound HMAC CSRF token in `X-CSRF-Token`.
- **Rate limiting and lockout:** the login route is limited to 20 requests per minute. After five consecutive failed attempts, an account is locked for 15 minutes. Login failures use uniform public error content, and unknown accounts receive a dummy Argon2 verification; exact network-level timing is not guaranteed.
- **Database privilege boundary:** separate migration and application roles are created. The app role receives only the SQL privileges required by implemented routes and cannot update/delete audit rows; audit triggers reject update, delete, and truncate attempts.

## 7. Audit trail

`audit_log` is append-only at the application and database layers. Database triggers reject `UPDATE`, `DELETE`, and `TRUNCATE`; the application database role has only `SELECT` and `INSERT` access. Each event contains an actor/role when available, request metadata, document reference when applicable, action, allowed/denied outcome, reason, and request ID. The log avoids exposing document titles to administrators unless the administrator independently has metadata access.

An append takes a transaction-scoped advisory lock, reads the previous row hash (or a zero initial link), creates a canonical representation, computes HMAC-SHA256 using `AUDIT_HMAC_SECRET`, and inserts `prev_hash` and `row_hash`. The audit write is in the same transaction as the associated database action. Denied attempts are recorded; if the audit append cannot be persisted, the request does not silently report success.

Run `npm run verify-chain` to verify continuity and recompute each row's HMAC with the configured audit key. The administrator verification endpoint uses the same verifier. A valid check proves consistency against the supplied secret and currently visible rows; it cannot detect an attacker who can rewrite the database and also obtain the HMAC key, prevent deletion/restoration by a sufficiently privileged database operator, or provide external durability/non-repudiation. Independent chain-head anchoring is not implemented.

## 8. Revocation design

Grant revocation updates active grant state, is serialized against document downloads, and is audited in the transaction. Authorization and search consult current grant state instead of relying on a cached permission. At token redemption, the subject and live grant are checked again; revoking access therefore also blocks an unused token. User deactivation and role changes revoke active sessions, and each session lookup checks current activity.

Revocation takes effect on the next serialized access check. It cannot retract bytes already delivered to a client or remove a local copy that was previously downloaded. The advisory locks serialize competing operations and can reduce throughput on the affected document; authorization adds a database policy query to protected operations. The system does not promise to cancel a response after bytes have already left the server.

## 9. AI suggestion feature

The optional suggestion feature uses only document metadata (title, description, category, owner display name); it does not send file contents. The default deterministic provider does not require an external AI service. Provider output is validated and limited to eligible active users. A suggestion is not a grant and cannot widen access: the owner must submit a separate decision, which follows the normal authorization path. Both suggestion generation and the owner's decision are audited.

## 10. Testing and verification

These are results from commands run in this checkout now, not copied from prior documentation. The local Docker engine was unavailable and `127.0.0.1:5432` refused connections, so database-backed checks could not complete.

| Command | Result |
|---|---|
| `npm run typecheck` | **PASS** — TypeScript check exited 0. |
| `npm run lint` | **PASS** — ESLint exited 0. |
| `npm test` | **FAIL / BLOCKED** — 13 test files: 11 passed, 2 failed; 71 tests: 63 passed, 1 failed, 7 skipped. The authorization integration setup failed to connect to PostgreSQL at `127.0.0.1:5432`; one security-foundation assertion failed because its expected migration grant text was not found in the combined migration contents. |
| `npm run build:all` | **PASS** — typecheck, server compilation, and Vite production build completed successfully. |
| `npm run mutation-check` | **INCOMPLETE / FAIL** — 12 mutations were attempted: 8 were killed by tests and 4 reported runner errors after Vitest exited nonzero. Database-dependent mutations could not be validated with PostgreSQL unavailable. |
| `npm run verify-chain` | **BLOCKED / FAIL** — could not connect to PostgreSQL at `127.0.0.1:5432`; no live chain row count or validity result was available. |

The test failure and unavailable database are reported rather than represented as passing results. The current `docker info` probe also failed because the Docker Desktop Linux engine pipe was not present. Re-run integration tests, mutation checks, and chain verification after starting Docker/PostgreSQL.

## 11. Threat model summary

The current [THREATS.md](../THREATS.md) contains **57** numbered threats: **44 closed**, **8 mitigated**, and **5 knowingly accepted**. “Mitigated” is not equivalent to closed: several migration/trigger protections are tested by inspecting schema text but do not have live PostgreSQL privilege/trigger integration coverage.

The knowingly accepted items are:

| Threat-register item | Why it remains accepted |
|---|---|
| #36: distinguish missing from inaccessible documents by timing | Status/body are the same, but database work and network scheduling are not constant-time. |
| #37: distinguish login account states by timing | Public responses are uniform and unknown users get a dummy hash check, but network-level constant timing cannot be guaranteed by these tests. |
| #52: heuristic scanner misses malware | `local-basic` is demo-grade and may miss unknown, obfuscated, encoded, or unrecognized threats; production requires a real scanner. |
| #55: public Cloudflare quick-tunnel link | The temporary tunnel has no edge authentication and anyone with its URL can reach the public app endpoints; application authorization still applies. |
| #56: public demo accounts used on an exposed deployment | Account names and local default password are public by design. Production seeding requires an explicit password, but demo accounts must still be changed or disabled before sensitive use. |

## 12. Demo accounts

| Role | Email | Password | Notes |
|---|---|---|---|
| admin | `admin@trustvault.local` | `TrustVault-Local-Demo-2026!` | Local seed default; override with `SEED_DEMO_PASSWORD` |
| owner one | `owner.one@trustvault.local` | `TrustVault-Local-Demo-2026!` | Local seed default; override with `SEED_DEMO_PASSWORD` |
| owner two | `owner.two@trustvault.local` | `TrustVault-Local-Demo-2026!` | Local seed default; override with `SEED_DEMO_PASSWORD` |
| viewer one | `viewer.one@trustvault.local` | `TrustVault-Local-Demo-2026!` | Local seed default; override with `SEED_DEMO_PASSWORD` |
| viewer two | `viewer.two@trustvault.local` | `TrustVault-Local-Demo-2026!` | Local seed default; override with `SEED_DEMO_PASSWORD` |
| viewer three | `viewer.three@trustvault.local` | `TrustVault-Local-Demo-2026!` | Local seed default; override with `SEED_DEMO_PASSWORD` |

These are local demo accounts created by the seed script. The password is public in this repository. Any internet-facing deployment must set its own SEED_DEMO_PASSWORD and reseed.

The table shows the local default from `scripts/seed-password.ts`. Production seeding refuses to proceed if `SEED_DEMO_PASSWORD` is missing or blank; do not reuse the local demo password in a deployment.

## 13. Environment variables

Never commit `.env` or put secret values in documentation, logs, screenshots, or issue reports. The minimum below distinguishes application validation from deployment recommendations.

| Variable name | Purpose | Minimum / validation | How to generate or set |
|---|---|---|---|
| `DATABASE_URL` | Runtime application connection to PostgreSQL | Must parse as `postgres:` or `postgresql:` URL with host and database path; no explicit character minimum. | Set a connection URL for the `trustvault_app` role. Keep credentials private; do not paste the URL into documentation or logs. |
| `DB_MIGRATION_URL` | Migration connection using the separate migrator role | Required by migration/deployment workflow; no explicit app-config length check. | Set a connection URL for `trustvault_migrator`; use the matching private database password. |
| `POSTGRES_MIGRATOR_PASSWORD` | Compose initializes the migration role with this password | Compose requires a nonempty value; EC2 setup generates 64 hexadecimal characters. | Generate a fresh random value, for example locally with `openssl rand -hex 32`. |
| `POSTGRES_APP_PASSWORD` | Compose initializes the runtime application role | Compose requires a nonempty value; EC2 setup generates 64 hexadecimal characters. | Generate a separate fresh random value, for example `openssl rand -hex 32`. |
| `MASTER_KEY` | Wraps per-file encryption keys | At least 32 UTF-8 bytes, checked by startup config. | Generate a unique random secret of at least 32 bytes with a cryptographic random generator. |
| `AUDIT_HMAC_SECRET` | HMAC key for audit-chain creation and verification | At least 32 UTF-8 bytes, checked by startup config. | Generate a unique random secret of at least 32 bytes; keep it separate from `MASTER_KEY`. |
| `SESSION_SECRET` | Signs session-bound CSRF tokens | At least 32 UTF-8 bytes, checked by startup config. | Generate a unique random secret of at least 32 bytes; do not reuse another key. |
| `SEED_DEMO_PASSWORD` | Password set by the seed script for all seeded demo accounts | Production seed requires a nonblank value; EC2 setup additionally requires 12 or more URL-safe characters. | Choose a unique deployment-only password. Production seed has no public default. |
| `MALWARE_SCANNER` | Selects the upload scanner | Optional; only `local-basic` is implemented. Unset/unsupported means uploads fail closed. | Leave unset to disable uploads or use `local-basic` only for a demo. |
| `PORT` | API listen port | Optional; local Compose sets `3000`. | Set to the desired port if the process environment requires it. |
| `STORAGE_DIRECTORY` | Private encrypted-file directory | Optional; defaults to `storage`; Compose uses `/app/storage`. | Set a private, persistent directory with appropriate filesystem permissions. |
| `NODE_ENV` | Runtime mode; production also makes the seed password mandatory | Optional for local development; EC2 service sets `production`. | Set `production` only with deployment secrets and a private deployment environment. |

## 14. Run locally on Windows

Prerequisites: Node.js 20, npm, Docker Desktop with its Linux engine running, and a correctly configured private `.env`. Docker Compose publishes PostgreSQL only on `127.0.0.1:5432`; do not expose that port to a public interface.

In PowerShell, from the repository root:

```powershell
Set-Location D:\trustvalut
$env:Path += ";D:\"
npm ci
Copy-Item .env.example .env
```

Edit `.env` locally: replace every placeholder with fresh unique values, set the PostgreSQL URLs/passwords and three application secrets, and optionally set a custom `SEED_DEMO_PASSWORD`. Do not use the checked-in placeholders as operational secrets. Then start the local stack:

```powershell
$env:Path += ";D:\"
npm run start:local
```

The script checks that Docker is running, starts the local PostgreSQL container, waits for port 5432, runs migrations and the idempotent seed, then starts the API and Vite UI if they are not already healthy.

- UI: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:3000`
- Health check: `http://127.0.0.1:3000/healthz`

On Windows with an existing deployment or in another terminal, add `$env:Path += ";D:\"` before invoking project commands as requested by the local setup instructions.

## 15. Deploy on Amazon Linux EC2

The repository's `deploy/ec2/` files implement a demonstration setup, not a hardened production deployment.

1. Create an Amazon Linux EC2 instance and restrict the security group's **SSH ingress to your IP address only**. Do not open PostgreSQL or the app's port to the internet. The service is bound locally and exposed by the tunnel.
2. Connect as `ec2-user`, then clone the public repository into the exact expected directory:

   ```bash
   git clone https://github.com/RamGopalImadabathini/trustvault.git /home/ec2-user/trustvault
   cd /home/ec2-user/trustvault
   ```

3. Run the checked-in setup script as `ec2-user` (not root):

   ```bash
   bash deploy/ec2/setup.sh
   ```

   The script installs Docker/Git/OpenSSL, enables Docker, installs the pinned Compose plugin and `cloudflared`, installs Node 20 through NVM, prompts for a deployment-specific seed password, creates a mode-600 `.env` with generated private credentials if one does not already exist, starts the local database, runs `npm ci`, build, migrations, and production seed, installs the systemd units, and enables/starts the app and tunnel services.

4. Inspect service health and the generated link:

   ```bash
   sudo systemctl status trustvault.service
   sudo systemctl status trustvault-cloudflared.service
   bash deploy/ec2/show-link.sh
   ```

   The service definitions are `deploy/ec2/trustvault.service` and `deploy/ec2/trustvault-cloudflared.service`. The first runs the built production app; the second runs `cloudflared tunnel --url http://127.0.0.1:3000` and logs output to `/home/ec2-user/tunnel.log`.

The `trycloudflare.com` quick-tunnel URL is temporary, may change when the tunnel restarts, is not an access-controlled or durable production hostname, and can be used by anyone who obtains it. The quick tunnel has no edge authentication. Use a managed, authenticated ingress and production monitoring/scanning/backup controls before sensitive internet-facing use.

## 16. Problems encountered and fixes

Some setup incidents below are reported in the project brief but are not individually recorded in tracked files; those are marked as not independently verifiable rather than presented as commit-proven history.

| Problem | Resolution / evidence |
|---|---|
| Docker engine did not start; WSL/Docker Desktop was unavailable. | `scripts/start-local.ps1` explicitly checks `docker info` and stops with an instruction to start Docker Desktop. Start the Linux engine/WSL backend before `npm run start:local`. This checkout's Docker probe currently fails because the Docker Desktop engine pipe is absent. |
| C: drive ran out of space. | The incident and its exact cleanup are not recorded in tracked files, so the fix cannot be independently verified here. Ensure enough free space for Docker images, PostgreSQL volumes, npm dependencies, and builds; configure Docker storage appropriately. |
| `ECONNREFUSED` on port 5432 because the database port was not published. | The current `docker-compose.yml` publishes PostgreSQL as `127.0.0.1:5432:5432`, and the local startup script waits for `127.0.0.1:5432`. This verifies the current configuration, but the earlier incident is not separately captured in the commit log. |
| Node was not on `PATH`. | The documented PowerShell setup adds `$env:Path += ";D:\"` before invoking tools; Node.js 20 is the package's required major version. The particular machine-level PATH change is not represented as a repository commit. |
| Uploads returned 503 because no scanner was wired. | This is intentionally fail-closed when no scanner is configured. Commit `25d83dc` added the `local-basic` demo scanner; setting `MALWARE_SCANNER=local-basic` enables uploads for demos, but does not provide production malware detection. |
| `argon2` native dependency build requirements and Node version mismatch. | Use the package's declared Node `>=20 <21` runtime and install dependencies with `npm ci`. Machine-specific compiler/build-tool remediation is not fully documented in the repository. |
| Amazon Linux 2023 `curl-minimal` package conflict. | The issue and a specific package-removal workaround are not recorded in the checked-in deployment script or README, so the exact fix cannot be verified. `deploy/ec2/setup.sh` uses the system `curl` command and otherwise installs `docker`, `git`, and `openssl` with `dnf`. |
| GitHub stub history needed merging into the implementation history. | Commit `6b8f7c0` is explicitly titled “merge initial GitHub stub history”; the current history contains that merge and subsequent implementation commits. |

## 17. Deliberately not built and known limitations

- **Production malware engine:** only the heuristic `local-basic` demo scanner exists. Integrating and operating ClamAV or another maintained production scanner is still required for real sensitive files.
- **External audit anchoring:** the chain is stored in the same PostgreSQL trust domain. There is no independent external anchor or immutable offsite archive.
- **SSO / enterprise identity:** no SAML/OIDC integration or enterprise identity lifecycle is implemented.
- **Group-based document access:** group tables/organizational concepts do not create group grants. Access remains user-specific and document-specific.
- **External sharing links:** no anonymous/public sharing links are implemented; short-lived download tokens are still bound to a user and checked against current access.
- **Folder permission inheritance:** intentionally omitted so folder movement or visibility cannot broaden document access.
- **Production ingress and operational hardening:** the EC2 quick tunnel is temporary and has no edge authentication; production TLS termination, durable domain, backups, monitoring, patch lifecycle, and disaster recovery require deployment work.
- **Independent timing guarantees:** response-body parity is tested, but API/database/network execution is not constant-time. Login timing also cannot be guaranteed constant at network level.
- **Instant recall of downloaded bytes:** revocation stops later checks, not a file already delivered or copied by a recipient.
- **Large-file streaming:** the upload limit is 10 MiB; decryption integrity is verified before delivery and the design is not a large-file streaming architecture.
- **Live DB verification gap:** the threat register explicitly calls out missing live PostgreSQL validation for some role-grant and trigger claims. In this run, DB-backed tests and chain verification were also unavailable because the local database did not start.
- **AI provider configuration:** the default is deterministic; a production AI provider, governance, monitoring, and provider credentials are not part of this repository's core deployment.

## 18. Submission checklist and links

- [x] Main project document created at `docs/PROJECT_DOCUMENTATION.md`.
- [x] README links to the full project documentation.
- [x] Timeline and security claims are tied to tracked history/source; unverifiable setup incidents and test blockers are labeled.
- [x] The demo identities and local seed password are identified as public local-demo credentials; the production seed override is called out.
- [x] No `.env` values, encryption/HMAC/session keys, connection strings containing passwords, or personal email addresses are included.
- [ ] Start Docker/PostgreSQL and rerun the database integration suite, mutation checks, and `npm run verify-chain`; resolve the currently observed test assertion before claiming a fully passing suite.
- [ ] Review this submission and push the documentation commit to the default branch.

Repository: [github.com/RamGopalImadabathini/trustvault](https://github.com/RamGopalImadabathini/trustvault)
