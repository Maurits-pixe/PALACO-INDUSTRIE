# PALACO INDUSTRIE — PostgreSQL Independent Continuity Contract v2.6 (DRAFT / HOLD)

This release adds a **reference storage schema and application adapter**, not an installed or independently certified durability service.

## Artifacts

- `distribution/sql/independent-floor-highwater-v2.6.sql`: a PostgreSQL schema and high-watermark table for an independently administered authority database.
- `distribution/postgres-independent-continuity.js`: `createPostgresIndependentContinuity({namespace,query})` returns a branded v2.5 independent authority adapter, suitable for the v2.5 strict registry factory.
- `tests/distribution-postgres-independent-continuity.test.js`: parameterization, monotonic behavior across adapter re-creation, invalid responses, abort and disconnection tests, using a **simulated query callback**, not a live PostgreSQL server.

## Compare-and-advance semantics

The adapter issues one parameterized SQL statement:

```sql
UPDATE palaco_continuity.floor_highwater
SET epoch = $2, minimum_last_seen_ms = $3
WHERE namespace = $1 AND epoch <= $2 AND minimum_last_seen_ms <= $3
RETURNING epoch, minimum_last_seen_ms;
```

An existing provisioned namespace row is required. PostgreSQL updates acquire a row lock, so competing updates to the same namespace cannot both return successful regression. `rowCount` MUST be exactly `1`, with one returned row matching both proposed safe integers. Failure, SQL errors, abort, missing rows and mismatches all deny. The adapter does not perform INSERT, UPSERT or automatic provisioning.

## Required operator controls (NOT provisioned by this PR)

- Deploy the schema in a **separate** trusted PostgreSQL cluster/service, independent from the SQLite challenge registry and its backup/restore chain.
- Provision namespace rows through an independently reviewed administrative process; protect bootstrap against accidental reset.
- Restrict runtime DB credentials to precisely authorized namespaces and necessary columns. Explicitly revoke broad/public schema and table privileges; assess row-level security and tenant isolation before exposing any SQL endpoint. No credentials or GRANT statements are included.
- Enforce TLS, trust-root pinning where required, network access policies, connection quotas and abort-aware query cancellation. A rejected or timed-out update may already have committed remotely; subsequent requests must rely on monotonic state, not optimistic rollback.
- Verify independent durability, backup protection and rollback resistance through operational controls. PostgreSQL alone does not provide immutable external monotonicity against a privileged administrator restoring old backups.

## Boundary

Code and mocked-query tests can establish SQL statement shape and adapter fail-closed behavior, but **not** linearizability, crash-recovery or server-protected durability of a real deployment. No production service has been configured, connected or authorized. Keep authorization `DENY`, `GO-13 HOLD`, no merge, install or deployment.
