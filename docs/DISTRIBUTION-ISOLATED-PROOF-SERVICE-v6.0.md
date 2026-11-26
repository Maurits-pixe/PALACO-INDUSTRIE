# PALACO INDUSTRIE — Isolated Compact Proof Service v6.0

**Status:** DRAFT / DENY / GO-13 HOLD. No merge, production publication, installation, key activation, release or deployment.

## Interfaces

`distribution/manifest-proof-issuer-v6.0.js` is a **read-only, process-local proof issuer** over the ordered v5.8 transparency `entry_digest` rows. It issues v5.9 inclusion or consistency proofs for bounded request sizes (1 to 10,000), using `LIMIT 10001` and strictly checking exact row count, consecutive sequence, lowercase SHA-256 digests and requested tree size. Invalid inputs, missing rows, gapped archives or query errors are `BLOCKED`. It never signs roots, writes to the database or authorizes distribution.

`distribution/manifest-proof-verification-service-v6.0.js` is a **separate, read-only verifier** accepting an issued proof envelope of at most 4,096 UTF-8 bytes. It checks the namespace, non-authorizing purpose/status, exact proof structure, reconstructed Merkle roots, an **independently supplied out-of-band root pin for every tree size**, and then authenticates the corresponding independent Ed25519-signed PostgreSQL root(s) via the existing v5.9 verifier. Both old and new roots must be independently pinned for a consistency claim. Forged paths, different responses claiming the same tree size, restored signing roots, oversized envelopes, expired/revoked key metadata as supplied by the trust source, or unavailable independent pins block.

Both adapters expose only issue/verify methods and return `authorization=DENY`, `go13=HOLD`, and false for advancing, restoring, reconciling, synchronizing, installation and publication. They have no HTTP listener, bearer token, signing private key, release handler, or database write API. Separate query functions in CI model but do not physically enforce independent process/host identities.

## Tests

`tests/distribution-manifest-proof-service-v6.0.test.js` tests valid inclusion, all compact prefix consistency sizes, bounded and malformed issuer requests, missing/gapped log rows, independent same-size split-view pins, invalid signed checkpoints, unavailable roots, payload-size exhaustion, cross-namespace replay and aborted checks.

`tests/postgres-manifest-proof-service-v6.0.test.js` provisions two isolated logical databases on the same disposable PostgreSQL 17 CI host. The issuer reads a synthetic three-entry append-only registry; a second DB holds independently signed SHA-256 Merkle roots at sizes 1 and 3. Inclusion and consistency verify using separate pins and signing roots. A privileged one-sided issuer schema restore removes entries 2–3: new proof issuance blocks, while already-issued original evidence remains independently verifiable. Altered claimed roots and consistency nodes block.

## Residual limitations

- This is a **process-local API prototype**, not a deployed web service. The issuer's caller must have controlled access to an immutable complete audit log; the verifier must live under separate credentials, process/host permissions, and independently retained pinned root history in a production build.
- The independent pin provider is a trusted dependency; compromised or colluding pin administrators can authorize an alternative synthetic tree. CI pins live in memory; no production KMS, key transparency, external audit quorum or independent hosting has been provisioned.
- The Merkle proofs establish membership and append-only consistency of the **v5.8 entry digests** only. Historical underlying Ed25519 publication statements, hash-linked v5.8 lineage and key rotation need separate verification. The tests' synthetic PostgreSQL `entry_digest` values deliberately do not stand in for independently proven historic real-world data.
- A preexisting archived proof is not a new verification of currently restored source; an unavailable primary should never be interpreted as a grant of ongoing synchronization or release privileges.
- Out-of-band pin comparison detects conflicting answers only for exact trusted tree sizes available from the independent pin provider. This is not a gossip protocol, consensus system, remote proof publication service or a public transparency witness.
- PostgreSQL CI logical databases share a server and administrator; independent deployment and disaster recovery domains remain unverified.

**GO-13 HOLD and authorization DENY remain mandatory.**