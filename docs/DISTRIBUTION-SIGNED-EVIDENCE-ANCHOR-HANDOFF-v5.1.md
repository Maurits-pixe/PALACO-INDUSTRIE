# PALACO INDUSTRIE — Independently Receipted Full Evidence Anchor v5.1

**Status:** DRAFT / DENY / GO-13 HOLD. Not deployed. No releases or merge.

## Scope

`distribution/signed-evidence-anchor-handoff-v5.1.js` encodes a domain-separated, deterministic Ed25519 handoff for the full v5.0 SHA-256 evidence-chain root. Two distinct, separately pinned identities sign the canonical issuer handoff and a recipient-bound acknowledgement. An external trusted policy supplies the current time, previous anchored sequence and digest, and issuer/recipient public keys. Expiry, revoked keys, mismatching recipient/nonce, invalid signatures, replay and cross-namespace scopes all reject.

`distribution/signed-evidence-anchor-receiver-v5.1.js` is an opt-in trusted adapter. It first reads the **complete source evidence commitment rows**, re-verifies every historical Ed25519 handoff and recipient signature against independently supplied per-sequence historical signing roots, checks adjacent signed witness lineage and the SHA-256 digest of each full signed dossier, then calculates the v5.0 succession digest. It checks this against the signed next root, checks the live current external root and two signatures, then sends one parameterized PostgreSQL statement that atomically updates the independently stored root (CAS) and inserts a nonce/receipt row. Any unreachable source, external witness, mismatching digest or SQL conflict is DENY/HOLD; no fallback or automatic reconciliation.

`distribution/sql/signed-evidence-anchor-receipts-v5.1.sql` defines a unique `(namespace,nonce)`, `(namespace,sequence)` and `(namespace,handoff_digest)` replay-resistant receipt table with UPDATE/DELETE/TRUNCATE blocking triggers. The external DB runtime role should receive only namespace-scoped SELECT, column-scoped head UPDATE, and receipt INSERT; no owner/DDL privileges.

## Test boundaries

`tests/distribution-signed-evidence-anchor-handoff-v5.1.test.js` covers dual signatures, tampered fields, expiry, revoked keys, replay, source mismatch and storage failures. `tests/postgres-signed-evidence-anchor-handoff-v5.1.test.js` exercises a disposable restricted PostgreSQL writer and separate source/root databases. It verifies the receipt and root advance once, rejects reuse, forbidden SQL and privileged source restoration while the independent root remains.

## Security limitations (must not be conflated with production)

- The v5.1 receiving step re-verifies historic Ed25519 signatures and full evidence digests through its **mandatory independent historicalRootsProvider**. The authenticity and revocation dates of those supplied historical roots still require independent governance, immutable key history and effective-date revocation policy; a compromised trusted root provider could fabricate a plausible history.
- The source and root databases in CI are separate logical databases, but they share the same PostgreSQL 17 server and administrator. They do not prove independent custody, resilience to a coordinated restore, external operators, mTLS, production secrets, key custody or protected credentials.
- The root advance and receipt record are atomic within **one external PostgreSQL database**, not with the separate source archive. Between writes, divergence is a HOLD condition. The new module never automatically repairs discrepancies.
- A PostgreSQL owner/superuser can drop triggers or roll back the external witness itself; the evidence root must be protected under separate physical and organizational custody.
- A signed receipt proves possession of private keys and acknowledgement bytes, not an independently attested person, real external storage or authorization. There is no HTTP ingress, production migration or operational release path.

**No merge, installation, publication, production role provisioning or deployment.**