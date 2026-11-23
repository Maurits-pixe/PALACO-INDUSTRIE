# PALACO INDUSTRIE — Cross-Store Rollback Rejection v2.9 (DRAFT / HOLD)

## Test objective

Prove that a restored **SQLite challenge-registry backup** cannot silently resume issue/consume operations when a physically separate PostgreSQL continuity witness retains a stronger clock-floor value.

## Executed test design

`tests/postgres-independent-rollback-rejection.test.js` uses an isolated PostgreSQL 17 service in GitHub Actions, a temporary on-disk SQLite registry, test-only Ed25519 keys and signed clock-floor proofs. A snapshot is taken when SQLite's last-seen clock is 1000 and PostgreSQL's witness is epoch 5, floor 1000.

The registries then advance: SQLite reaches 3000, while independent PostgreSQL accepts epoch 6 and floor 2000. The test restores only the old SQLite file from the snapshot; PostgreSQL is not rolled back.

The strict `createIndependentlyGuardedChallengeRegistry` must then reject issuing a new challenge with the valid, fresh-nonce signed floor 2000, because SQLite's pre-update stored clock is only 1000. It must also reject a stale but validly signed floor 1000 because the independent PostgreSQL witness already advanced to floor 2000. A restored pending challenge must remain unconsumed, SQLite must remain unchanged, and the higher PostgreSQL witness must remain intact.

## Scope and limitations

- This is **real PostgreSQL and real SQLite** in one disposable GitHub runner. It is not a multi-server deployment, independently secured hardware root or a production backup-restore procedure.
- The test illustrates independent state comparison only if the PostgreSQL continuity database **does not share the same rollback/backup/administrative domain** as the restored SQLite registry.
- It does not withstand rolling back both stores together, modifying database state with owner privileges, compromising signing keys, or falsely attesting high-watermarks with a malicious signer.
- Signing keys and namespaces are generated or provisioned only for the isolated CI experiment. No user database, secrets or external services are modified.
- No application release authority is provided: `authorization=DENY`, `go13=HOLD`, `mayInstall=false`, `mayPublish=false`.

Verification requires success from the `postgres-continuity-integration` GitHub Actions job for the exact final commit. No merge or deployment.
