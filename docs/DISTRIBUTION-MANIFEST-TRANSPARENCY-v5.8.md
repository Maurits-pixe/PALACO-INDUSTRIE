# PALACO INDUSTRIE — Signed Manifest Transparency Ledger v5.8

**Governance:** Draft PR #36; `authorization=DENY`, `go13=HOLD`. No merge, installation, key activation, public release, automatic repair or production migration.

## Implemented cryptographic contract

`distribution/manifest-transparency-v5.8.js` provides a read-only, ordered verifier for the **complete historical v5.7 publication observations**. Every entry commits to its exact sequence, prior entry SHA-256 digest, canonical domain-separated publication-view bytes, observer key ID and original Ed25519 signature bytes. Each historical observation signature is independently validated against an out-of-band trusted observer root. The verifier rejects gaps, reordering, duplicate same-rotation observer, forged signatures, altered bytes, invalid predecessor linkage, manifest rotation regressions and authentic simultaneous split-view.

An **independently stored and Ed25519-signed** latest transparency checkpoint binds the namespace, final event sequence, final event hash, checkpoint observer and observation instant. The verifier requires a distinctly provided checkpoint query adapter and pinned checkpoint public key, and compares its signed value with the recomputed complete history. The caller must also supply a previously trusted checkpoint sequence and SHA-256 digest **out of band**; the verifier recomputes the historical prefix at that sequence. It refuses a different prefix even when the latest signed checkpoint is otherwise valid.

`distribution/sql/manifest-transparency-v5.8.sql` defines an immutable, sequential PostgreSQL log with database enforcement of genesis, immediate predecessor sequence and digest, unique per-rotation observer, and UPDATE/DELETE/TRUNCATE rejection. A transaction-scoped PostgreSQL advisory lock serializes concurrent writers per namespace. A separate signed checkpoint table has monotone UPDATE and DELETE/TRUNCATE rejection. Database column constraints and triggers alone do **not** verify Ed25519 signatures or the correct SHA-256 event digest; the trusted verifier does.

## CI coverage

`tests/distribution-manifest-transparency-v5.8.test.js` exercises six groups: valid complete signed history, omission/reordering/broken links, restored log and stale checkpoint, signature/event tampering, authentic split-view, and unavailable trust sources or abort.

`tests/postgres-manifest-transparency-v5.8.test.js` provisions two disposable PostgreSQL 17 **logical** databases, inserts two independently signed observations and a signed checkpoint, verifies the complete chain, denies skipped genesis and ordinary mutation, then simulates a privileged one-sided ledger schema restore with only the first event. The unchanged independent checkpoint at sequence 2 causes `TRANSPARENCY_CHECKPOINT_HEAD_MISMATCH` and permanent DENY/HOLD.

## Limitations and production prerequisites

- A chain of hashes and two signed observers is not a public Certificate Transparency deployment, a global consensus log, or proof of independent hosting. Both CI databases still share one PostgreSQL server and administrator. A coordinated compromise of both and the out-of-band pins can defeat the prototype.
- The signed latest checkpoint is an **observation claim**. This module does not sign, distribute, rotate, activate or publish manifests; no HTTP route or production integration is enabled.
- A database superuser can remove triggers and reconstruct data. A direct writer can insert hashes without cryptographic admission. The read-only verifier blocks invalid histories only when its independently trusted signing roots and checkpoint pins remain intact.
- Source reads and checkpoint reads are not a distributed atomic snapshot. Honest concurrent updates may temporarily return BLOCKED; this is intentional, never permission for automatic reconciliation.
- Verification caps complete histories at 10,000 entries. A production-scale design needs independently witnessed segmented checkpoints, inclusion/consistency proofs, and authenticated observer gossip to detect selective withholding across clients.
- The signed observations cover only registered manifest rotation views, not every historical production key lifecycle event. v5.5 independently pinned key history and v5.6 triple-signature key rotation remain separate prerequisites.

**Safe completion criterion:** only GitHub CI evidence on the Draft branch is accepted. `main` remains unchanged and GO-13 remains HOLD.