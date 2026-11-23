# PALACO INDUSTRIE — Independent Authority Anchor v3.9 (DRAFT / HOLD)

## Capability

`distribution/sql/authority-anchor-highwater-v3.9.sql` provisions a separately managed PostgreSQL schema/table, `palaco_authority_anchor.latest`, with an immutable namespace, integer authority revision, SHA-256 authority-history digest and a `BEFORE UPDATE` regression guard. Admin provisioning is **not** performed by the runtime. The SQL trigger refuses same/lower revision, skipped revision, digest reuse and namespace changes (SQLSTATE 23514). Owner/superuser bypass and restoring the witness volume remain threats.

`distribution/postgres-authority-anchor.js` exposes `createAuthorityAnchorStore({namespace,query})`. A trusted PostgreSQL query adapter may read the current revision/digest using parameterized SQL. `verifyAnchoredAuthorityRotation()` checks a full old-to-new signed transition (outgoing key, incoming key, two independent reviewers) against an **unmodified**, externally hosted anchor row. Missing, malformed or stale state fails closed. The verifier never grants release authority.

**Security hardening:** arbitrary `compareAndAdvance` is private to the module and is not exposed on the store. `store.advanceVerified(previous,next,record,endorsements,pinnedReviewers,signal)` first checks the current independent anchor, verifies the four-party signed rotation, then performs a single atomic parameterized compare-and-advance. A concurrent race or replay fails the PostgreSQL CAS. The store returns booleans, not deploy or key-rotation privileges.

## CI evidence

New `tests/postgres-authority-anchor.test.js` runs both mock denial tests and a real disposable PostgreSQL 17 scenario. It provisions a test anchor at revision 10, verifies a four-signature proposed revision 11, advances the independent anchor via the **verified path**, then proves the signed historical revision-10 proposal cannot be reused. It also asserts that direct SQL rollback is rejected by the database trigger.

The CI runner deliberately administers both test stores using disposable credentials; this is a contract and regression test, **not** proof of two operationally independent organizations or immutable storage. Real-world anti-rollback requires the anchor database and protected role/backup domain to be separate from the roster signing authority. The adapter does not provision or attest that isolation, independent reviewer identities, transport authentication, KMS, or PostgreSQL secrets.

## Governance and integration

The v3.8 roster authority verifier and v3.4 HTTP startup interlock are unchanged. This new external anchor adapter is **not bound** to the live server: distribution routes remain HTTP 503 with an authenticated session and valid CSRF. A successful diagnostic proof returns `authorization=DENY`, `go13=HOLD`, `mayRotate=false`, `mayInstall=false`, `mayPublish=false`. Database CAS updates only an isolated authority-reference value and must not be confused with operational authority-key rotation.

Draft PR #36: no merge, publication, installation, deployment, production table migration or production authority change.
