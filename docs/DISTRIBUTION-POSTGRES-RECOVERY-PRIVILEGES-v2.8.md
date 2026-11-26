# PALACO INDUSTRIE — PostgreSQL Recovery and Least Privilege v2.8 (DRAFT / HOLD)

v2.8 extends the **isolated GitHub Actions PostgreSQL 17 integration suite** with a real container crash/restart experiment and explicit runtime-role privilege checks.

## Artifacts

- `distribution/sql/independent-floor-guard-v2.8.sql`: an administrator-installed `BEFORE UPDATE` trigger that rejects decreasing signer epochs, decreasing clock floors and changing namespaces. This is defense in depth in addition to the parameterized compare-and-advance SQL from v2.6.
- `tests/postgres-crash-recovery.test.js`: two-phase test. Phase `prepare` commits a high-watermark. GitHub Actions sends `SIGKILL` to the **disposable PostgreSQL service container**, restarts that same container, checks readiness and invokes phase `verify` to confirm the committed watermark, deny regressions, and check the trigger.
- `tests/postgres-runtime-privileges.test.js`: creates a **test-only** non-owner role, grants only necessary SELECT/UPDATE columns and schema USAGE, uses RLS policies to restrict the role to a provisioned namespace, then tests that INSERT, DELETE, TRUNCATE, ALTER TRIGGER, cross-namespace visibility and direct clock regression are rejected.
- `.github/workflows/auth-regression.yml`: runs both extra tests only against the ephemeral CI PostgreSQL service; the production package and credentials remain untouched.

## Verified boundaries

- Crash test covers **abrupt termination/restart of the same container with its writable data volume**, not backup restoration or host loss. It does not establish independent hardware-monotonic durability, immutable audit logs, high availability, or multi-cluster consensus.
- The CI role and password are disposable and intentionally not reusable in any deployment. The runtime never receives schema ownership or permission to disable triggers.
- A privileged database owner/superuser can still restore old backups or change triggers, policy and state. The true independent anti-rollback trust boundary needs separately protected administration, credential isolation, protected backups and operational attestation.
- The trigger is not a substitute for authenticated service requests or allowed caller scope. The CI RLS policy is illustrative, explicitly test-only and **not applied by this PR** to any real database.
- `npm test` does not contact PostgreSQL unless `PALACO_TEST_POSTGRES=1`, and the phase-specific crash test requires `PALACO_TEST_PHASE` set by the isolated CI job.

Authorization remains DENY; GO-13 remains HOLD. No database in a user account has been connected, created, migrated, or altered. No merge, production installation or publication is permitted.
