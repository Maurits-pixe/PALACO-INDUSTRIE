# PALACO INDUSTRIE — Recovery & Rollback Preflight v0.8 (DRAFT)

Pure read-only validation of a restored trust anchor against an independently signed recovery witness. Exports `witnessPayload(witness)` and `assessRecoveryPreflight(namespace, restoredAnchor, witness, endorsement, independentRoots)` in `distribution/recovery-preflight.js`.

A witness contains `schemaVersion: palaco.distribution.recovery-witness.v1`, namespace, nonnegative integer sequence and lowercase SHA-256 digest. The signed payload is domain-separated and ends with a newline. Verification requires Ed25519 and an **independently pinned** active, nonrevoked recovery root.

The restored anchor must match BOTH the witness sequence and digest exactly. Older anchors block as `RESTORED_ANCHOR_ROLLBACK`; newer anchors block as `WITNESS_BEHIND_ANCHOR`; an equal sequence with a different digest blocks as `RECOVERY_DIGEST_MISMATCH`.

## Boundary

The independent witness must come from **outside** the database or backup under consideration. Otherwise an attacker can roll back both the anchor and witness. Pinned roots must come from protected, authenticated local configuration, never from restored or downloaded files. This function **does not** verify the database snapshot contents, restore any data, establish wall-clock freshness, provide hardware-backed monotonic storage, or authorize an installation. Witness issuance and secure persistence are external requirements.

All outcomes force `authorization=DENY`, `go13=HOLD`, `mayRestore=false`, `mayRotate=false`, `mayInstall=false`, `mayPublish=false`.

Run `node --test tests/distribution-recovery-preflight.test.js`.
