# PALACO INDUSTRIE — Atomic Signed Receipt Evidence v5.0 (DRAFT / HOLD)

## New opt-in receiver

`distribution/atomic-signed-evidence-receiver-v5.js` is a strictly opt-in alternate to the v4.7 recipient. It validates both Ed25519 signatures and pinned signer trust roots, then performs a **single PostgreSQL data-modifying CTE statement** containing witness-head compare-and-swap, nonce receipt insertion, complete signed handoff/receipt evidence insertion and SHA-256 evidence commitment insertion. A failed constraint/unique key/foreign key cancels that statement's writes, with no partial head advancement. It is not mounted in HTTP routes or production.

`distribution/signed-evidence-v5.js` computes a domain-separated SHA-256 commitment covering the original canonical handoff and receipt bytes and **both** signature key IDs and base64 signature bytes, not just receipt metadata. `signedEvidenceChain` builds a cumulative cryptographic root over the ordered receipt metadata and complete evidence commitment digests. `createSignedEvidenceVerifier` recalculates the full root against a separate, read-only external anchor and re-verifies every historic Ed25519 pair against independently pinned historical trust roots, including predecessor/successor signed lineage continuity. Missing evidence, tampering, fork/replay, unavailable roots or mismatching external high-watermark block.

## Storage

`distribution/sql/signed-evidence-commitments-v5.0.sql` provisions write-once signature evidence commitment entries with foreign keys to the immutable v4.9 evidence table. PostgreSQL BEFORE UPDATE/DELETE/TRUNCATE triggers guard against normal SQL mutation. `distribution/sql/signed-evidence-external-anchor-v5.0.sql` provisions a separate, monotone root with rollback triggers. These scripts are admin-only provisioning contracts; they are **not** production migrations.

## Tests

`tests/distribution-signed-evidence-v5.test.js` checks signature-byte commitment, historic signature verification, missing evidence and external root failure, incomplete handoffs, invalid receipts and atomic receiver failure semantics.

`tests/postgres-atomic-signed-evidence-v5.test.js` exercises two consecutively signed complete receipts and the separate root against disposable PostgreSQL 17 databases, confirms invalid signatures do not write, replay blocks, and persisted evidence is joined to its immutable commitments. It also demonstrates rejection after a privileged operator removes/recreates the evidence storage while the independently held root remains unchanged.

## Important limitations

- The new receiver and root verifier are **opt-in**. Existing v4.7 receiver behavior is unchanged, and v5.0 cannot retroactively populate missing original signatures.
- Evidence-root updates are separately administrated; **no distributed transaction** couples the PostgreSQL receipt store to its independent external root. During the handoff/reconciliation window mismatches are HOLD, never silently repaired.
- The CI databases share a PostgreSQL server and administrator, so this demonstrates separate logical databases and one-sided rollback, not independent custody, credentials, physical infrastructure, KMS or operator trust.
- A privileged PostgreSQL owner can disable triggers or replace both databases. A direct SQL-writer credential could bypass application-side signature validation. Production requires an isolated ingestion principal and independently administered roots and transport.
- Historical revocation policy must provide authentic effective-date key validity. This prototype rechecks trusted historical roots provided to it, and records are at most 10,000 per verification pass.
- The read-only chain verifier does not establish global atomic snapshots across services and grants **no** restoration, synchronization, publication, key rotation or release capability.

**Governance:** authorization `DENY`, `GO-13 HOLD`, Draft PR #36. No merge, deployment, installation, publication, or production database changes.