# TrustVault phase 1 threats

This phase covers the scaffold and migration baseline. Each entry names the attack, mitigation, covering test, and honest current status. Schema-text tests do not substitute for testing effective PostgreSQL privileges or trigger behavior against a running server.

| # | Attack | Mitigation | Covering test name | Status |
|---|---|---|---|---|
| 1 | Public schema privileges allow arbitrary reads or writes to tables by default | The migration revokes all table/sequence privileges from `PUBLIC` before granting specific app-role access | `phase 1 security foundation rejects public schema privileges on the migration` | mitigated: migration assertions exist, but live PostgreSQL grants are not integration-tested |
| 2 | Broad application DB privileges allow row mutation where least privilege is required | The app role grants only `SELECT, INSERT` on the core domain tables | `phase 1 security foundation restricts the application DB role to least-privilege reads and inserts` | mitigated: migration assertions exist, but effective runtime privileges are not integration-tested |
| 3 | A database user can mutate `audit_log` rows to remove evidence | Trigger declarations block `UPDATE`, `DELETE`, and `TRUNCATE` | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` | mitigated: migration assertions exist, but trigger behavior is not integration-tested |
| 4 | Missing hash-chain fields allow tampered audit rows | `prev_hash` and `row_hash` are required to be exactly 32 bytes | `phase 1 security foundation requires a hash-chain row key in audit_log` | mitigated: schema assertions exist; HMAC generation and verification are later-phase work |
| 5 | Audit rows without request correlation are hard to investigate | `request_id` and `outcome` are required and constrained | `phase 1 security foundation requires request correlation and outcome fields for every audit row` | mitigated: schema assertions exist; audit writes are later-phase work |
| 6 | Hash-chain continuity fields are omitted | The schema includes `prev_hash` and `row_hash` | `phase 1 security foundation stores the previous hash in every audit record before hashing the row` | mitigated: schema assertions exist; chain continuity and HMAC verification are later-phase work |
| 7 | App role can mutate audit rows through explicit grants | The app role receives only `SELECT, INSERT` on `audit_log`, and triggers reject row mutation | `phase 1 security foundation keeps the app DB role from mutating audit rows through UPDATE or DELETE grants` | mitigated: migration assertions exist, but effective runtime privileges are not integration-tested |
| 8 | Public schema grants remain broad despite restricted app grants | The migration explicitly revokes table and sequence access from `PUBLIC` | `phase 1 security foundation never exposes the app role to public privileges over the schema` | mitigated: migration assertions exist, but live PostgreSQL grants are not integration-tested |
| 9 | Startup accepts malformed database URLs | `loadConfig` validates PostgreSQL URL syntax and rejects unsupported schemes | `loadConfig rejects unsupported or malformed database URLs: http://localhost:5432/trustvault` | closed |
| 10 | Startup continues with missing or undersized secret material | `loadConfig` requires each secret to have at least 32 UTF-8 bytes and reports invalid variable names only | `loadConfig reports all missing and undersized variables together`; `loadConfig measures secrets in UTF-8 bytes` | closed |

## Security exception and tradeoff

This phase deliberately uses Fastify 5.12.5+ although the initial stack note specified Fastify 4. npm audit reported an authentication-bypass advisory covering Fastify 4 with no patched 4.x release, so this plan prefers the patched Fastify 5 line. This is an explicit compatibility exception, not a claim that all future Fastify use is automatically secure.
