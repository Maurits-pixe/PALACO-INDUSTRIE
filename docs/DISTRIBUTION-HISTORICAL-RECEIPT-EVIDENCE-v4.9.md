# PALACO INDUSTRIE — Historical Receipt Signature Evidence v4.9 (DRAFT / HOLD)

## Implemented capability

`distribution/sql/receipt-signed-evidence-v4.9.sql` adds `palaco_incident_witness.receipt_evidence`, a strictly append-only sidecar for the existing v4.7 receipt metadata. Each entry references the original `(namespace,sequence)` and preserves the complete signed issuer handoff payload, issuer Ed25519 signature, recipient receipt payload and recipient Ed25519 signature. Immutable row/statement triggers reject UPDATE, DELETE and TRUNCATE. All provisioning is confined to disposable CI. The existing receipt schema and receiver v4.7 are unchanged.

`distribution/historical-receipt-evidence.js` exposes two deliberately separate non-authorizing adapters:

- `createHistoricalReceiptArchiver()` validates a complete pair of historic signatures against independently supplied, per-sequence pinned signing roots, verifies signed receipt timestamps and the handoff digest, and uses a single parameterized `INSERT … SELECT` to bind evidence to the exact pre-existing sequence, nonce, digest and recipient ID. It does not expose arbitrary SQL writes.
- `createHistoricalReceiptVerifier()` reads the ordered receipt metadata LEFT JOINed to every historic signed evidence row, recalculates the v4.8 cumulative SHA-256 succession root against a distinct external root query, then revalidates **both** Ed25519 signatures for **every** historical receipt. Any missing sidecar evidence, revoked/unavailable root, forged signature, invalid timestamp, modified receipt, mismatching chain root or aborted operation causes BLOCKED / DENY / GO-13 HOLD. It never repairs, publishes or advances an authority.

Historical signature validation uses the **signed receipt acceptance time**, not the current date, so legitimately expired handoffs can be reverified retrospectively. The trust-root provider must independently maintain the historic key roster and key-revocation semantics. A key revoked today is rejected when the provider marks it revoked; effective-time revocation policy is not yet modeled.

## Test coverage

`tests/distribution-historical-receipt-evidence.test.js` checks four correct historical signatures, absent evidence, modified sender/recipient signatures, modified signed bytes, expired receipt time, changing recipient binding, rollback against the independent root, revoked/unavailable historical trust roots, archiver rejection of tampered signature, storage outages, abort and ambiguous responses.

`tests/postgres-historical-receipt-evidence.test.js` executes a real two-receipt historical archive in disposable PostgreSQL 17 and independently anchors their metadata root in a separate CI PostgreSQL database. It confirms all four signatures, forbids update/delete/truncate, simulates privileged deletion and recreation of the signed evidence table, and proves verification fails on missing evidence despite an intact metadata root. A forged evidence backfill is rejected.

## Explicit limits

- This is an **opt-in historical evidence sidecar and read-only verifier**; v4.7 live receiver has not been migrated to atomically persist the new payload. Existing receipts cannot be verified until their original signed handoff and receipt files are securely recovered and validated. Missing evidence means HOLD, not synthetic reconstruction.
- External root currently commits to the **receipt metadata**, not the full signature bytes. Replacing evidence with a *different valid pair of signatures* under unchanged trusted keys and handoff bytes would not change that root; independent evidence-digest anchoring remains a needed hardening step.
- The two disposable CI databases still share the same server and administrator. Independent production storage, TLS-mTLS, role isolation, historical key custody and real backup/restore independence are not deployed.
- A table owner / PostgreSQL superuser can bypass table triggers. An operator with raw INSERT privileges can attempt to bypass application verification. Keep historical archival database credentials private to a trusted process.
- Only up to 10,000 receipts are verified per historic chain pass. Enforce external checkpoint policy before scaling beyond that cap. Cross-store reads are not a distributed atomic snapshot.
- The live HTTP distribution routes remain blocked (`ingress:null`). A signed receipt does not grant synchronization, repair, key issuance, release or installation.

**Governance:** `authorization=DENY`, `go13=HOLD`; Draft PR #36 only, no merge, installation, publication or production deployment.