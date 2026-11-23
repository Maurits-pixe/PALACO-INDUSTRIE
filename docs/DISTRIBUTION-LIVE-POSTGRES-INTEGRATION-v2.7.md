# PALACO INDUSTRIE — Live PostgreSQL Continuity Integration v2.7 (DRAFT / HOLD)

## Purpose

This build adds an isolated **real PostgreSQL 17** integration test to the existing synthetic adapter suite. It does not create, migrate, connect, or mutate any user's PostgreSQL/Supabase project or production database.

## CI isolation

`.github/workflows/auth-regression.yml` gains `postgres-continuity-integration` with an ephemeral PostgreSQL 17 GitHub Actions service container and test-only credentials. It sparse-checks out `distribution/` and `tests/`, installs a Node PostgreSQL driver **only within this CI job**, and runs `node --test tests/postgres-live-continuity.test.js`. The ordinary `npm test` suite skips the live test unless `PALACO_TEST_POSTGRES=1`.

## Verified scenarios expected

- Applying the schema against PostgreSQL, followed by explicitly controlled test-only administrative namespace bootstrap.
- A parameterized monotonic UPDATE through the v2.6 `createPostgresIndependentContinuity` adapter.
- Rejection of separately decreasing signer epoch or clock floor.
- A newly constructed adapter maintaining continuity by consulting the same PostgreSQL row.
- PostgreSQL row locking: a competing stale compare-and-advance waits for the first transaction to COMMIT, then fails without overwriting the stronger state.
- A ROLLBACK of a tentative update does not persist that update.
- A missing namespace row cannot be automatically inserted by the runtime adapter.

## Limitations

An ephemeral PostgreSQL container is **not** an independently protected, rollback-resistant authority service. The test does not simulate external backups being restored, compromised administrators, physical host failures, network partitions, quorum consistency or operator disaster recovery. Real privilege separation, credential handling, TLS and trusted roots must be reviewed before any deployment. A test success is evidence only for local database SQL semantics, not operational trustworthiness.

All outputs and gates remain `authorization=DENY` and `GO-13=HOLD`. This change is Draft only: no merge, deployment, installation or authority grants.
