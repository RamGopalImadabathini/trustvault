# TrustVault Implementation Plan

## Workspace inspection

The workspace contained no files at inspection time. In particular, `.github/copilot-instructions.md` was not present, so there were no repository instructions to read. No existing implementation, dependencies, migrations, tests, or secrets were found to assess for violations such as Express, JWT, bcrypt, authorization checks outside `authorize()`, audit title leakage, or hardcoded keys.

This is a plan only. No application code has been written.

## 1. Threat model and trust boundaries

### Security objectives

- A document's content and document-specific metadata are available only to its owner or a currently active user with a sufficient explicit, unexpired document grant. The admin role alone never grants content access.
- All document access attempts, including denied and not-found-equivalent attempts, are recorded in the append-only audit log. Audited reads must fail closed if their audit write fails.
- Revocation and account deactivation take effect on the next authorization decision. Previously issued sessions, download tokens, and grants must not bypass current checks.
- Unauthorized and nonexistent documents produce the exact same `404` status and response body. Search results, counts, facets, errors, versions, exports, and audit views must not expose unauthorized document information.
- File storage and the audit chain remain protected if the web root, database application role, or a single application component is compromised, to the extent possible under the key and deployment boundaries below.

### Assets

- Original files, every document version, file hashes, and wrapped per-file encryption keys.
- Document metadata, ownership, grants, folder association, and version history.
- User credentials, active sessions, download-token state, and AI suggestion/decision records.
- Audit events and the integrity of their HMAC chain.
- Master encryption, session, and audit HMAC secrets.

### Principals and trust boundaries

| Boundary / principal | Trust level and allowed capabilities | Main threats and controls |
|---|---|---|
| Anonymous client | Untrusted; may attempt login and public operational endpoints only | Uniform login failures, rate limiting/lockout, CSRF protections where applicable, strict headers, route registry and deny-by-default behavior |
| Authenticated owner/viewer/admin browser | Authenticated but all request parameters, headers, filenames, metadata, and timing are untrusted | Server-side session lookup and live authorization on each request; never rely on client role, cached access, or UI filtering |
| Browser ↔ API | Network boundary | TLS in deployment, `Secure`/`HttpOnly`/`SameSite=Strict` session cookie, CSRF token/origin checks for state changes, CSP and security headers |
| Fastify application | Trusted policy-enforcement boundary, but exposed to malformed requests and implementation bugs | Patched Fastify 5.12.5+ (Fastify 4 has no fix for the audit-reported authentication-bypass advisory), strict schemas, parameterized SQL, one `authorize(actor, documentId, action)` policy function, mandatory route registry action, tests/mutation checks |
| Application ↔ PostgreSQL | Separate service boundary | Least-privilege app DB role; parameterized SQL; transactions and locks for authorization plus file-read coordination; audit inserts in same transaction; no app role UPDATE/DELETE/TRUNCATE on audit |
| Application ↔ file storage | Private storage boundary; files are hostile input and never web-served | Random opaque storage keys outside web root, AES-256-GCM per-file data keys, master-key wrapping, streamed authenticated reads, upload validation, scan hook |
| Application ↔ AI provider | External/untrusted processor | Metadata-only payload, injection-resistant prompt construction, schema-validated bounded output, existing-active-user allowlist, provider timeout/error handling, no grant side effects |
| Deployment operator / host | Privileged operational boundary; can access process environment and storage | Secrets supplied outside source control, restricted host and backups, documented key rotation/restore, no secret logging |
| PostgreSQL superuser / audit-key holder | Powerful residual threat | A DB superuser who also obtains `AUDIT_HMAC_SECRET` can forge the chain; mitigate with independent periodic external chain anchoring/export and state this limitation honestly |

### Attacker capabilities and key abuse cases

- Guess document IDs, enumerate users, manipulate filters, request another user's versions/downloads, and compare response bodies, status, timing, counts, facets, and errors.
- Replay a token or session after revocation, deactivation, password change, or role change; race a revoke against a download.
- Submit path traversal names, mismatched MIME/magic bytes, oversized files, archive bombs, malformed archives, and malicious metadata.
- Attempt mass assignment of roles/ownership, grant escalation, edit-holder grant creation, grants to inactive/nonexistent accounts, and folder-based inherited access.
- Attempt audit tampering, bypassing audit on refusals/errors, triggering audit-write failures, and exploiting concurrent chain appends.
- Inject instructions into metadata presented to the AI provider; ask it to suggest inactive/nonexistent users or to directly grant access.

## 2. Data model

PostgreSQL 16. UUID primary keys are generated server-side. Timestamps are `timestamptz` in UTC. All constraints below are database constraints where practical, with matching application validation. Sensitive secrets and raw credentials/tokens are never persisted in plaintext. The application DB role is separate from the migration/owner role.

### `users`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `email` | `citext` | Not null, unique; normalized for login |
| `display_name` | `text` | Not null; bounded length |
| `password_hash` | `text` | Not null; Argon2id encoded hash |
| `role` | `text` | Not null; check in `admin`, `owner`, `viewer`; assigned only by authorized administration, never mass-assigned from user input |
| `is_active` | `boolean` | Not null, default true |
| `failed_login_count` | `integer` | Not null, default 0, check nonnegative |
| `locked_until` | `timestamptz` | Nullable |
| `password_changed_at` | `timestamptz` | Not null |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `updated_at` | `timestamptz` | Not null, default `now()` |
| `deactivated_at` | `timestamptz` | Nullable; consistent with `is_active` |

Indexes: unique normalized email; partial indexes supporting active-user selection and lockout lookup. Deactivation and role/password changes revoke all sessions in the same transaction.

### `sessions`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `user_id` | `uuid` | Not null, FK to `users(id)` with cascade on user deletion (prefer deactivation over deletion) |
| `secret_hash` | `bytea` | Not null, unique; hash of random opaque cookie secret, never the raw cookie |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `last_seen_at` | `timestamptz` | Not null |
| `expires_at` | `timestamptz` | Not null, check greater than `created_at` |
| `revoked_at` | `timestamptz` | Nullable |
| `csrf_secret` | `bytea` | Not null; server-side CSRF secret material |
| `created_ip` | `inet` | Nullable |
| `user_agent` | `text` | Nullable, bounded and treated as untrusted |

Indexes: `secret_hash` unique; `(user_id, expires_at)` for session invalidation/expiry cleanup. Cookie is opaque, `HttpOnly`, `Secure`, `SameSite=Strict`; no JWT.

### `folders`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `name` | `text` | Not null, bounded and sanitized as metadata |
| `parent_id` | `uuid` | Nullable self-FK; organization only, never authorization |
| `created_by` | `uuid` | Not null, FK to `users(id)` |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `updated_at` | `timestamptz` | Not null, default `now()` |
| `deleted_at` | `timestamptz` | Nullable soft-delete timestamp |

Indexes: `(parent_id, name)` as appropriate to the chosen folder naming policy; `created_by`. No folder permission inheritance or authorization join is allowed.

### `documents`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `owner_id` | `uuid` | Not null, FK to `users(id)` |
| `folder_id` | `uuid` | Nullable FK to `folders(id)`; organization only |
| `title` | `text` | Not null, bounded; untrusted metadata |
| `description` | `text` | Nullable, bounded; untrusted metadata |
| `declared_mime_type` | `text` | Not null, normalized and validated against detected content |
| `original_filename` | `text` | Not null, sanitized display name only; never used as a storage path |
| `current_version_id` | `uuid` | Nullable FK to `document_versions(id)`; deferred constraint or transactional update handles insert ordering |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `updated_at` | `timestamptz` | Not null, default `now()` |
| `deleted_at` | `timestamptz` | Nullable soft-delete timestamp |

Indexes: owner and folder organization queries, plus partial active-document index. Search indexes must only be used inside a permission-filtered SQL query. Soft deletion does not itself grant or bypass authorization.

### `document_versions`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `document_id` | `uuid` | Not null, FK to `documents(id)` |
| `version_number` | `integer` | Not null, positive; unique with `document_id` |
| `storage_key` | `text` | Not null, unique random opaque key; no user-controlled path components |
| `wrapped_data_key` | `bytea` | Not null; per-file AES-256-GCM data key wrapped by `MASTER_KEY` |
| `key_wrap_nonce` | `bytea` | Not null |
| `key_wrap_auth_tag` | `bytea` | Not null |
| `file_nonce` | `bytea` | Not null; unique/random as required by encryption design |
| `file_auth_tag` | `bytea` | Not null |
| `sha256` | `bytea` | Not null, exactly 32 bytes; digest of original plaintext content |
| `size_bytes` | `bigint` | Not null, nonnegative and bounded by configured upload limit |
| `detected_mime_type` | `text` | Not null, derived from magic-byte inspection |
| `created_by` | `uuid` | Not null, FK to `users(id)` |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `scan_status` | `text` | Not null; constrained values such as `pending`, `clean`, `rejected`, `error` |

Constraints/indexes: unique `(document_id, version_number)`; index `(document_id, created_at)`. Files are not stored in the database or web root. Upload policy includes size cap, extension allowlist, magic-byte/MIME match, sanitized filename, traversal defense, archive/zip-bomb limits, malware hook, attachment disposition, and `nosniff`.

### `document_grants`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `document_id` | `uuid` | Not null, FK to `documents(id)` |
| `user_id` | `uuid` | Not null, FK to `users(id)` |
| `level` | `text` | Not null, check in `read`, `edit`, `manage` |
| `granted_by` | `uuid` | Not null, FK to `users(id)` |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `expires_at` | `timestamptz` | Nullable; if set, must be in the future at grant time |
| `revoked_at` | `timestamptz` | Nullable |
| `revoked_by` | `uuid` | Nullable FK to `users(id)` |

Constraints/indexes: one current grant per `(document_id, user_id)` via a partial unique index where not revoked, or retain grant history in separate immutable grant rows with a corresponding active-grant uniqueness rule. Index `(user_id, document_id)` for permission joins and `(document_id, user_id)` for grant management. Access queries require active user, non-revoked grant, and `expires_at IS NULL OR expires_at > transaction_timestamp()`. No folder-derived grants.

### `groups`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `name` | `text` | Not null, bounded |
| `created_by` | `uuid` | Not null, FK to `users(id)` |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `updated_at` | `timestamptz` | Not null, default `now()` |
| `deleted_at` | `timestamptz` | Nullable |

Constraint: unique active group name according to the organization policy.

### `group_members`

| Column | Type | Constraints / purpose |
|---|---|---|
| `group_id` | `uuid` | Not null, FK to `groups(id)` |
| `user_id` | `uuid` | Not null, FK to `users(id)` |
| `added_by` | `uuid` | Not null, FK to `users(id)` |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `removed_at` | `timestamptz` | Nullable |

Primary key `(group_id, user_id)` for current membership, with membership history retained using a separate history row or an append-only event policy if needed. Group membership is organizational only in this plan: it never grants document access.

### `download_tokens`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `token_hash` | `bytea` | Not null, unique; hash of a cryptographically random bearer token |
| `user_id` | `uuid` | Not null, FK to `users(id)` |
| `document_id` | `uuid` | Not null, FK to `documents(id)` |
| `version_id` | `uuid` | Not null, FK to `document_versions(id)` |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `expires_at` | `timestamptz` | Not null, short lifetime; greater than `created_at` |
| `redeemed_at` | `timestamptz` | Nullable; single-use redemption |
| `revoked_at` | `timestamptz` | Nullable |

Indexes: unique token hash; `(user_id, document_id, expires_at)`. Redemption locks the token row, consumes it once, and performs a fresh live authorization check in the same transaction as the associated document/version read.

### `ai_suggestions`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `uuid` | Primary key |
| `document_id` | `uuid` | Not null, FK to `documents(id)` |
| `requested_by` | `uuid` | Not null, FK to `users(id)` |
| `provider` | `text` | Not null; provider identifier or `rule_based` |
| `input_metadata_hash` | `bytea` | Not null; records metadata input without copying file content |
| `suggestions` | `jsonb` | Not null; schema-constrained list of existing active user IDs and bounded rationale |
| `created_at` | `timestamptz` | Not null, default `now()` |
| `decision` | `text` | Nullable; constrained `accepted`, `rejected`, `modified` |
| `decided_by` | `uuid` | Nullable FK to `users(id)` |
| `decided_at` | `timestamptz` | Nullable |

Suggestions cannot create or widen grants. The owner makes a separate, audited decision request; grant creation uses the normal grant route and authorization path. Do not store document content or secrets in AI records.

### `audit_log`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | `bigint` | Primary key, generated identity |
| `event_id` | `uuid` | Not null, unique, request/event correlation |
| `occurred_at` | `timestamptz` | Not null, default `clock_timestamp()` |
| `actor_id` | `uuid` | Nullable FK to `users(id)`; null for anonymous attempts |
| `actor_role` | `text` | Nullable snapshot; constrained known role values when non-null |
| `ip_address` | `inet` | Nullable |
| `user_agent` | `text` | Nullable, length-bounded and untrusted |
| `document_id` | `uuid` | Nullable FK to `documents(id)`; identifier only, no title/content copied |
| `action` | `text` | Not null, constrained event/action name |
| `outcome` | `text` | Not null, check `allowed` or `denied` (plus explicitly documented system outcome if required) |
| `reason` | `text` | Not null, bounded non-sensitive reason code/text |
| `request_id` | `text` | Not null, bounded |
| `details` | `jsonb` | Not null, allowlisted non-content metadata only |
| `prev_hash` | `bytea` | Not null, exactly 32 bytes |
| `row_hash` | `bytea` | Not null, exactly 32 bytes; HMAC-SHA-256 over canonical row fields and `prev_hash` |

Constraints/indexes: indexes on `(occurred_at, id)`, `actor_id`, `document_id`, and `(action, outcome)` as needed. Audit rows are inserted in the same transaction as the action. App role receives only `INSERT` and `SELECT`; triggers reject `UPDATE`, `DELETE`, and `TRUNCATE`. A transaction-safe chain-head lock/serialization mechanism prevents concurrent writers from forking the chain. HMAC key `AUDIT_HMAC_SECRET` is outside the DB. A verify-chain CLI validates canonicalization and HMACs; external anchoring/export limits, but cannot eliminate, DB-superuser/key-holder forgery.

## 3. Route table

Every registered route has an explicit action in a startup-validated route registry. `authorize(actor, documentId, action)` is the sole permission-policy function; `documentId = null` is used for global actions. Authentication/session and CSRF middleware supply identity and request integrity but do not duplicate document permission rules. Every attempt that can touch a document, including denied attempts and not-found-equivalent responses, is audited. For document routes, denial and absence return the identical `404` body, for example `{"error":"Not found"}`.

`N/A` means there is no document authorization target; the route still declares an action and is checked through the central policy entry point/global policy. Route names below are proposed API surfaces and may be adjusted during implementation without weakening the controls.

| Method | Path | Required authz action | Audit event written | Denied response |
|---|---|---|---|---|
| `GET` | `/healthz` | `system.health` | Operational health access where configured; no secrets/details | `503` generic if unhealthy |
| `POST` | `/api/auth/login` | `auth.login` | Login success or denied, including uniform failure reason code | Uniform `401` body/timing for bad credentials, unknown/inactive/locked account |
| `POST` | `/api/auth/logout` | `auth.logout` | Session revoked / denied | Generic `401` if no valid session |
| `GET` | `/api/auth/me` | `auth.session.read` | Session profile read | Generic `401` |
| `POST` | `/api/auth/password` | `auth.password.change` | Password changed or denied; revoke other sessions | Generic `401`/`403` without account disclosure |
| `GET` | `/api/documents` | `document.list` | List attempt; include outcome | Generic response; only authorized rows returned |
| `POST` | `/api/documents` | `document.create` | Upload/create allowed or denied, with document ID once allocated | Generic `404` for document-target authorization failures; validation errors do not disclose stored docs |
| `GET` | `/api/documents/:id` | `document.read_metadata` | Metadata read allowed or denied before response | Identical `404` body for absent or unauthorized |
| `PATCH` | `/api/documents/:id` | `document.edit_metadata` | Metadata edit allowed or denied | Identical `404` body for absent or unauthorized |
| `DELETE` | `/api/documents/:id` | `document.delete` | Soft-delete allowed or denied | Identical `404` body for absent or unauthorized |
| `POST` | `/api/documents/:id/restore` | `document.restore` | Restore allowed or denied | Identical `404` body for absent or unauthorized |
| `POST` | `/api/documents/:id/grants` | `document.grant` | Grant creation allowed or denied; never echo target user existence on denial | Identical `404` body for absent or unauthorized; generic validation failure otherwise |
| `GET` | `/api/documents/:id/grants` | `document.grants.read` | Grant listing allowed or denied | Identical `404` body for absent or unauthorized |
| `DELETE` | `/api/documents/:id/grants/:userId` | `document.revoke` | Revocation allowed or denied | Identical `404` body for absent or unauthorized |
| `POST` | `/api/documents/:id/transfer` | `document.transfer_ownership` | Ownership transfer allowed or denied, same transaction | Identical `404` body for absent or unauthorized |
| `GET` | `/api/documents/:id/versions` | `document.versions.read` | Version-list access allowed or denied | Identical `404` body for absent or unauthorized |
| `POST` | `/api/documents/:id/versions` | `document.version.create` | New version upload allowed or denied | Identical `404` body for absent or unauthorized |
| `GET` | `/api/documents/:id/versions/:versionId` | `document.version.read` | Version metadata access allowed or denied | Identical `404` body for absent or unauthorized |
| `POST` | `/api/documents/:id/download-tokens` | `document.download.issue` | Token issuance allowed or denied before returning token | Identical `404` body for absent or unauthorized |
| `GET` | `/api/downloads/:token` | `document.download.redeem` | Redemption/read allowed or denied before streaming; fail closed on audit failure | Identical `404` body for absent, invalid, expired, used, revoked, or unauthorized |
| `GET` | `/api/search` | `document.search` | Search attempt; no unauthorized counts/facets/results | Only permission-filtered results; generic response, no unauthorized counts/facets |
| `GET` | `/api/folders` | `folder.list` | Folder organization access attempt | Generic response; folder membership never implies document access |
| `POST` | `/api/folders` | `folder.create` | Folder creation attempt | Generic `403` for global-policy denial |
| `PATCH` | `/api/folders/:id` | `folder.edit` | Folder update attempt | Generic `404` or `403` per non-document policy; never reveals document authorization |
| `DELETE` | `/api/folders/:id` | `folder.delete` | Folder soft-delete attempt | Generic `404` or `403` per non-document policy |
| `GET` | `/api/admin/users` | `admin.users.read` | Admin user metadata view | Generic `403`; no role checks duplicated in handlers |
| `POST` | `/api/admin/users` | `admin.users.create` | User creation attempt | Generic `403`; role is server-controlled |
| `PATCH` | `/api/admin/users/:id` | `admin.users.manage` | User change/deactivation; sessions invalidated transactionally | Generic `403` |
| `GET` | `/api/admin/documents` | `admin.documents.metadata` | Admin document metadata view; no content/storage fields | Generic `403`; metadata only |
| `GET` | `/api/admin/audit` | `admin.audit.read` | Audit-view access attempt | Generic `403`; view contains no document content and is itself audited |
| `GET` | `/api/admin/audit/verify` | `admin.audit.verify` | Chain verification request and result | Generic `403`; no chain/key internals exposed |
| `POST` | `/api/documents/:id/ai-suggestions` | `document.ai.suggest` | Suggestion request, including provider/fallback outcome | Identical `404` body for absent or unauthorized |
| `POST` | `/api/documents/:id/ai-suggestions/:suggestionId/decision` | `document.ai.decide` | Owner decision recorded; any later grant is a separate audited grant request | Identical `404` body for absent or unauthorized |

Error handlers must not reveal SQL details, storage paths, existence, or grant state. Access to download content is logged before streaming starts; a failed audit insert prevents the stream. A stream already in progress cannot be recalled byte-for-byte; the lock/transaction policy and revocation behavior are detailed in section 6.

## 4. Permission matrices

### Role × action

Legend: `Y` means the role may invoke the action only when the central policy and resource-specific conditions succeed; `G` means only if explicitly granted the required document level; `—` means denied. Owner implicit manage applies only to documents they own. Admin never receives implicit document-content access.

| Action | Admin | Owner of document | Explicitly granted viewer/owner | No grant |
|---|---:|---:|---:|---:|
| Global health | Y | Y | Y | Y |
| Login/logout/session self-service | Y | Y | Y | Y |
| Manage users / change roles / deactivate | Y | — | — | — |
| Read admin document metadata | Y | — | — | — |
| Read admin audit metadata / verify chain | Y | — | — | — |
| List/search documents | Only explicit grants for documents; admin listing is metadata-only admin action | Y for owned documents | G (read+) | — |
| Read document metadata/content/versions | G (admin has no implicit grant) | Y | G (read+) | — |
| Edit document metadata / upload version | G (edit+) | Y | G (edit+) | — |
| Grant/revoke access | G (manage) | Y | G (manage) | — |
| Transfer ownership | G (manage), subject to transfer rules | Y | G (manage), subject to transfer rules | — |
| Soft-delete/restore | G (manage) | Y | G (manage) | — |
| Folder organization operations | Central global policy; role alone never reveals protected documents | Per folder policy | Per folder policy | Denied if policy fails |
| Request AI suggestion / record decision | G (manage) | Y | G (manage) | — |

Group membership has no document authorization effect. The table is a policy summary, not permission logic embedded in handlers; enforcement remains in `authorize()`.

### Grant level × document action

| Action | `read` | `edit` | `manage` | Owner (implicit manage) |
|---|---:|---:|---:|---:|
| Read permitted document metadata | Y | Y | Y | Y |
| Read/download a version | Y | Y | Y | Y |
| Search-match a document | Y | Y | Y | Y |
| Edit metadata / upload new version | — | Y | Y | Y |
| List current grants | — | — | Y | Y |
| Create/revoke grants | — | — | Y | Y |
| Transfer ownership | — | — | Y, subject to transfer rules | Y |
| Soft-delete/restore | — | — | Y | Y |
| AI suggestion and decision | — | — | Y | Y |

Rules: owner implicit manage is not stored as a grant; an explicit grant cannot exceed the grantor's effective level; edit holders cannot grant; only active existing users can receive grants; expiry and revocation are checked live; no folder inheritance.

## 5. Implementation phases

1. **Scaffold, migrations, and CI** — TypeScript, React/Vite, PostgreSQL 16, Docker Compose, Vitest/Supertest, ESLint, baseline CI, migration/DB-role setup, startup environment validation that lists all missing/short required variable names without values. Security exception: use patched Fastify 5.12.5+ instead of Fastify 4 because npm audit reports an authentication-bypass advisory covering Fastify 4 with no patched 4.x release.
2. **Authentication and sessions** — Argon2id, uniform login failures/timing, rate limit and lockout, opaque revocable DB sessions, secure cookie/CSRF, session invalidation on password change, deactivation, and role change; mass-assignment protections and security headers/CSP.
3. **`authorize()` + route registry + grants** — Central action model, startup failure for routes without declared actions, per-document grants and expiry, owner implicit manage, no folder inheritance, grant-level enforcement, identical 404 behavior, regression tests that remove/bypass individual checks.
4. **Encrypted storage, upload validation, and download** — Private random-key storage, per-file AES-256-GCM and wrapped data keys, file validation/scanning/hash, safe attachment headers, single-use short-lived user/document-bound tokens, live revalidation, transaction/lock scope for revoke/download races.
5. **Audit chain** — Same-transaction append-only audit writes, audit denied attempts, app DB privileges/triggers, canonical HMAC hash-chain implementation and concurrency control, fail-closed audited reads, verify-chain CLI, tamper and failure-injection tests.
6. **Search, folders, versions, and soft delete** — SQL permission joins inside search query, no post-filtering, no folder-derived access, version/history authorization on each route, soft-delete/restore policy, no count/facet leaks; tests verify query-level permission filtering.
7. **Admin view and anomaly flags** — Admin user/document metadata-only surfaces, audit viewer and verification result, no content access from admin role, bounded anomaly indicators with no extra access bypass.
8. **AI suggestion** — Metadata-only provider contract, prompt-injection handling, schema validation and active-user allowlist, deterministic no-key fallback, audit suggestion and separate owner decision, absolutely no grant creation by AI.
9. **Full tests, mutation check, and `THREATS.md`** — End-to-end authorization matrix, denied/not-found equivalence, all-route registry enforcement, search SQL checks, session/token revocation, race tests, audit tamper/failure tests, upload adversarial tests, check that deleting an authorization check causes tests to fail; map every threat claim to a real test and avoid unsupported “closed” claims.
10. **Deploy and README** — Production deployment configuration and operational checks, secret provisioning/rotation, backup/recovery and external audit anchoring, threat limitations, API/deployment instructions, and explicit cost/limits of immediate revocation and in-flight downloads.

## 6. Design decisions with real tradeoffs

1. **Revocation atomicity vs. download throughput.** Holding a database lock/transaction through a streamed file read gives deterministic revoke-vs-download ordering but can hold connections/locks for the duration of large downloads. Releasing the lock before streaming improves throughput but permits an already-authorized stream to continue after revocation. Initial safer choice: authorize, write audit, consume token, and open the file under a transaction/lock; define the transaction's linearization point and document that bytes already delivered cannot be recalled. Evaluate bounded streaming/lease design only with concurrency tests.
2. **Owner deletion and ownership transfer.** Soft delete/restore is reversible and auditable but retains encrypted data and metadata. Ownership transfer preserves continuity but changes implicit manage authority. Require an explicit audited transfer action and active recipient; avoid hard-delete in normal API paths.
3. **Grant history vs. a single mutable active grant.** A unique current-grant row is simple, while immutable grant history improves accountability. Initial choice: retain grant/revoke events in the audit log and maintain at most one active grant per user/document; decide whether a dedicated historical-grant table is warranted before migration implementation.
4. **Group feature scope.** Groups aid organization, but group-derived grants add indirect authorization, revocation complexity, and a larger attack surface. Initial choice: groups and membership are organizational only and never confer document access; any later group-grant feature needs separate approval and a revised threat model.
5. **File encryption and streaming.** Whole-file AES-GCM verification generally requires the authentication tag before treating all bytes as authenticated; streaming large files with a single GCM tag can expose unauthenticated plaintext before final verification. Initial choice: do not stream decrypted GCM plaintext to the client until integrity verification succeeds, or use a separately designed chunked authenticated format with per-chunk verification. This trades latency/disk buffering for confidentiality/integrity correctness.
6. **Audit chain serialization and availability.** A serialized chain-head lock prevents forks but can bottleneck writes. Initial choice: correctness-first serialized append in the same transaction; measure before considering partitioned chains, which complicate ordering and verification.
7. **External audit anchoring.** The HMAC chain detects modification only while the HMAC key remains outside the DB and trusted. A superuser with both DB and key can forge it. Initial choice: periodic external signed digest/export to an independently controlled destination, accepting added operations and retention requirements.
8. **Fastify major version vs. fixed stack request.** The requested Fastify 4 line has no patched release for the audit-reported authentication-bypass advisory. Security takes precedence: use patched Fastify 5.12.5+ and revalidate the API behavior/tests against it.
8. **AI provider privacy vs. suggestion quality.** External providers may improve suggestions but receive metadata and may retain it. Initial choice: deterministic local fallback always works; external provider use is opt-in/configured, metadata-only, minimized, and disclosed. Neither provider can alter grants.
9. **Search relevance vs. side-channel resistance.** Facets/counts and broad search can leak document existence even if rows are filtered afterward. Initial choice: apply active grant/owner authorization inside SQL before ranking, aggregation, pagination, and facet/count computation; accept the added query complexity and test SQL behavior directly.
10. **Admin visibility vs. least privilege.** Admin needs operational metadata/audit visibility but must not read content by role. Initial choice: separate metadata-only admin actions and document content actions; admin receives content only through a distinct explicit grant, like any other principal.
11. **Uniform authentication errors vs. support diagnostics.** Detailed login failures help operations but can enable account enumeration. Initial choice: identical public status/body and comparable timing for unknown, inactive, locked, and wrong-password cases; detailed reason codes remain restricted to audit/operations and never include secrets.
12. **Session lifetime and usability.** Short sessions reduce stolen-cookie exposure but increase reauthentication. Initial choice: bounded idle and absolute expiry, revocation checked against DB on each request, with values set as explicit configuration/documented policy rather than silent long-lived defaults.

## Approval gate

No application code, migrations, dependency manifests, or configuration have been changed. Wait for approval of this plan before implementation.
