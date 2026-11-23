# PALACO INDUSTRIE — Authority Anchor Isolation and Crash Recovery v4.0 (DRAFT / HOLD)

## Summary

v4.0 extends the independent PostgreSQL 17 authority anchor of v3.9 with disposable live tests for least-privilege runtime execution, PostgreSQL row-level security (RLS), and persistence across a **hard container kill**. It does not provision production roles or databases.

## Restricted role contract

`tests/postgres-authority-anchor-privileges.test.js` provisions an ephemeral `authority_anchor_runtime_ci` role in the disposable GitHub Actions database. The test grants schema USAGE, column-scoped SELECT and UPDATE (revision and digest only), and per-namespace RLS on `palaco_authority_anchor.latest`. It verifies a valid four-party signed rotation through the runtime adapter and denies replay, access to a second namespace, INSERT, DELETE, TRUNCATE, ALTER TABLE / trigger disabling, and revision rollback. This is a CI proof for a proposed database permission contract, **not** a production role migration.

## Crash recovery

`tests/postgres-authority-anchor-crash-recovery.test.js` runs in distinct prepare/verify invocations. During prepare it commits authority revision 41 and SHA-256 digest to the disposable PostgreSQL service. GitHub Actions sends SIGKILL to the PostgreSQL 17 Docker container and restarts that same container and volume. The verify invocation confirms persisted revision 41/digest, rejects a regression to revision 40 and a skipped revision 43 using the database trigger, and confirms the persisted head was not changed.

## Trust limits

- Live CI uses one disposable PostgreSQL instance and test-only credentials. It **does not demonstrate organizational independence** between the application, authority issuer and witness store.
- PostgreSQL owners and superusers can circumvent normal RLS/trigger constraints, change permissions, or replace database files. The design requires independent administrators, backups and operational controls. It is not Byzantine consensus, WORM storage, or a transparency log.
- The crash test proves durability across a process/container crash with its volume preserved, **not** robustness against an administrator deliberately restoring an old backup of the witness itself.
- The authority-anchor adapter remains separate from the live distribution HTTP routes. Neither tests nor source updates perform a production key rotation, deployment, merge, install or publication.

**Governance:** authorization `DENY`, GO-13 `HOLD`, PR #36 remains Draft. All distribution endpoints remain deliberately disabled on server startup.
