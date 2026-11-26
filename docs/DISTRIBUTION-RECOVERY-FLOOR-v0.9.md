# PALACO INDUSTRIE — Independent Recovery Floor v0.9 (DRAFT / HOLD)

This adds read-only verification of a restored trust anchor against an **independently signed high-watermark**. The public module `distribution/recovery-floor.js` exports `floorPayload(floor)` and `assessRecoveryFloor(namespace, restoredAnchor, floor, endorsement, independentlyPinnedRoots)`.

A floor is `{schemaVersion:"palaco.distribution.recovery-floor.v1", namespace, sequence, digest}` with a nonnegative integer sequence and lowercase SHA-256 digest. The Ed25519 endorsement uses `{algorithm:"Ed25519",keyId,signature}` and must validate against a separately pinned active, nonrevoked public root.

Only an **exact match** of restored sequence/digest and signed floor yields diagnostic readiness `FLOOR_MATCH`. Older restored checkpoints are rejected as `RECOVERY_BELOW_TRUSTED_FLOOR`; newer ones as `FLOOR_STALE`; hash conflicts as `FLOOR_DIGEST_CONFLICT`. All invalid proofs fail closed.

**Trust boundary:** This function cannot prove the floor is recent or monotonic. An attacker who can roll back both an old signed floor and the restored database may defeat this check. The floor MUST be fetched from or pinned by an independent rollback-resistant authority, never alongside the backup under restoration. Root trust configuration must also be authenticated separately. Issuance, durable monotonic persistence, root rotation, recovery execution and trusted-time policy remain outside this module.

Even on `FLOOR_MATCH`: `authorization=DENY`, `go13=HOLD`, `mayRestore=false`, `mayRotate=false`, `mayInstall=false`, `mayPublish=false`. No file or database is mutated.

Test locally with `node --test tests/distribution-recovery-floor.test.js`. Eight tests were executed against the local working copy with Node v22.16.0; GitHub CI must independently validate the committed version.
