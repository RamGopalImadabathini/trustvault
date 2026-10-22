# TrustVault

TrustVault is a secure document-sharing platform under active development.

## Development checks

Install dependencies with `npm ci`, then run:

```powershell
npm run typecheck
npm run lint
npm test
npm run build
npm run mutation-check
```

`npm run mutation-check` applies one source mutation at a time, runs the full Vitest suite, and restores the changed source file in a `finally` block before continuing. A mutation is `KILLED` only when at least one test fails. A surviving mutation or execution error makes the command fail.
The command also exits nonzero while any planned authorization target lacks a mutation adapter, so an incomplete Phase 1 run cannot be mistaken for a complete authorization mutation check.

### Phase 1 mutation results

Verified on 2026-10-22 against the current Phase 1 implementation:

| Mutation | Failing test(s) |
|---|---|
| Allow UPDATE on users through app DB role | `phase 1 security foundation restricts the application DB role to least-privilege reads and inserts` |
| Disable audit UPDATE protection | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` |
| Disable audit TRUNCATE protection | `phase 1 security foundation blocks update/delete/truncate mutations on audit_log` |
| Accept undersized secrets | `loadConfig measures secrets in UTF-8 bytes` |
| Accept non-PostgreSQL database URLs | `loadConfig rejects unsupported or malformed database URLs: http://localhost:5432/trustvault`; `loadConfig rejects unsupported or malformed database URLs: postgresql://[broken-host]/trustvault`; `loadConfig rejects unsupported or malformed database URLs: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Every `authorize()` call site | NOT TESTED; no call sites exist in Phase 1 |
| Route-registry authorization guard | NOT TESTED; not implemented in Phase 1 |
| Audit write call | NOT TESTED; not implemented in Phase 1 |
| Search grant filter | NOT TESTED; not implemented in Phase 1 |

The requested `authorize()` call-site, route-registry guard, audit-write, and search-grant mutations are **not tested in Phase 1**. The mutation runner reports them as `NOT TESTED` and exits nonzero; it does not claim they passed. Add feature-specific mutation adapters and behavioral tests when those controls are implemented in their planned phases. The current tests for migration SQL verify the scaffold's declared grants and triggers, not a live PostgreSQL permission boundary; Docker and the PostgreSQL client are not available in the current development environment.

## Configuration

Copy `.env.example` to `.env` and replace each placeholder with a unique secret before starting the stack. The server refuses to start unless `DATABASE_URL`, `MASTER_KEY`, `AUDIT_HMAC_SECRET`, and `SESSION_SECRET` are valid; secret values must each be at least 32 UTF-8 bytes. Never commit `.env` or real secrets.

## Security stack exception

The initial requested stack specified Fastify 4. npm audit reported a known authentication-bypass advisory covering the Fastify 4 line with no patched 4.x release. To avoid pinning a known vulnerable version, this repository uses patched Fastify 5.12.5 or newer within the selected major. See `PLAN.md` for the tradeoff.
