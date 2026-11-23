# PALACO INDUSTRIE — Mandatory Checkpoint Execution Gate v3.1 (DRAFT / HOLD)

## Purpose

`createCheckpointGuardedChallengeRegistry` is an explicit **opt-in strict factory** that requires both a v2.5 branded independent continuity authority and a v3.1 branded checkpoint execution gate. Neither `issue` nor `consume` can reach the SQLite writer transaction without a fresh, signed, externally anchored continuity checkpoint matching the live PostgreSQL high-watermark.

## Trust order — critical

1. Fetch and verify the fresh Ed25519 signed clock floor with a unique challenge nonce.
2. Fetch a fresh, separately signed checkpoint and an independently held chain anchor. Verify pinned root, signature, nonce, prior digest, sequence, epoch and floor, then read and verify the **UNMODIFIED** PostgreSQL row.
3. Only after successful checkpoint attestation, invoke the independent continuity authority's atomic compare-and-advance. Never update PostgreSQL before the checkpoint check: doing so could conceal a restored older witness.
4. Check in-process floor continuity and the independent signed clock floor inside SQLite `BEGIN IMMEDIATE` before issuing or consuming a challenge.

All external I/O precedes SQLite locking. Checkpoint operations use a deadline and abort signal; an uncooperative timed-out callback retains its local/shared capacity reservation until the underlying Promise settles. Failures return DENY/HOLD; an unsuccessful preflight cannot consume a challenge.

## Tradeoffs and limitations

- The gate is a **new strict factory**, not an automatic retrofit of legacy compatibility factories. Callers must explicitly adopt it, and the production application has not been deployed or migrated.
- This design may conservatively deny an operation when PostgreSQL has already advanced beyond the signed floor or when concurrent operations modify the row between attestation and compare-and-advance. Retry with a fresh, independently anchored checkpoint; do not bypass attestation.
- The `fetchIndependentAnchor` callback is **assumed** to derive anchors from a separate authenticated trust/rollback domain. This code does not supply, protect or attest a real external anchor service or signing keys.
- The strict flow cannot detect collusive rollback of PostgreSQL and the purported independent anchor provider. Live CI tests use generated keys and simulated external anchor callbacks, not independent production infrastructure.
- Tests include construction refusal, valid preflight, tampered signature, unavailable checkpoint, timed-out uncooperative requests, and an isolated real PostgreSQL rollback blocking both `issue` and `consume` before SQLite mutation.

All operations remain `authorization=DENY`, `go13=HOLD` for governance and release. No merge, deployment, installation, publication, signer provisioning or trust-root rotation.
