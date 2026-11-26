# PALACO INDUSTRIE — Compact Merkle Inclusion & Consistency Proofs v5.9

**Governance:** Draft PR #36; `authorization=DENY`, `GO-13=HOLD`. No merge, publication, key activation, installation or production deployment.

## Evidence construction

`distribution/manifest-merkle-proofs-v5.9.js` defines a compact, deterministic, domain-separated SHA-256 Merkle tree over **the original v5.8 signed transparency `entry_digest` values**, in their exact append order. `leaf(digest) = SHA256(0x00 || digest_bytes)`; `branch(left,right) = SHA256(0x01 || left_bytes || right_bytes)`. For a non-power-of-two tree, internal nodes are recursively split at the largest power of two smaller than the subtree size. This is an explicit v5.9 Merkle commitment distinct from the existing v5.8 linear SHA-256 chain.

`inclusionProof(entries,index)` returns a compact bottom-up sibling-hash path establishing that a particular v5.8 entry digest was in a signed Merkle root at a given tree size. `reconstructInclusion()` strictly validates index, size, hash format, exact proof depth and root. A caller with independently trusted signed root can verify membership without downloading the full history.

`consistencyProof(entries,oldSize)` returns two sets of maximal canonical aligned perfect-subtree hashes: the original prefix cover and the extension cover, both in chronological order. `reconstructConsistency()` checks canonical cover dimensions and recomputes the old and new tree roots from **the same, shared prefix commitments** using ordered perfect-subtree aggregation. The proof size is O(log n) hashes for each prefix/extension cover, without transmitting the complete log. Distinct domain-separated v5.9 Merkle roots must be independently anchored for both tree sizes.

`createRootVerifier()` obtains requested v5.9 Merkle checkpoints from an external read-only query adapter, independently verifies the checkpoint Ed25519 signatures with pinned reviewer public keys and compares the expected roots with the reconstructed inclusion or consistency roots. Every outcome is non-authorizing: all `may*` flags false, `DENY / GO-13 HOLD`. It exposes no signer, database writer, merge, recovery or release API.

## Storage and test evidence

`distribution/sql/manifest-merkle-checkpoints-v5.9.sql` defines a distinct, append-only table of signed Merkle roots `(namespace, tree_size)` with UPDATE/DELETE/TRUNCATE rejection. The signature is verified in the application verifier, not by SQL constraints. Database superusers remain able to reconstruct entire schemas.

`tests/distribution-manifest-merkle-proofs-v5.9.test.js` exhaustively tests Merkle inclusion for every index of sizes 1..37 and consistency for every pair of sizes 1..37. Additional negative cases cover truncated, reordered or forged proof hashes, injected hashes, invalid bounds, revoked signing roots, forged signed checkpoints, unreachable anchor, aborted checks and the absence of any write/release interface.

`tests/postgres-manifest-merkle-proofs-v5.9.test.js` exercises two disposable logical PostgreSQL 17 databases, authentic signed checkpoint roots at sizes 3 and 7, successful inclusion and append-only consistency verification, forged extension hashes, immutable root rows and privileged loss of the anchor storage. The verifier blocks on anchor loss instead of trusting unanchored logs.

## Limitations and safeguards

- The Merkle proof authenticates **membership of a `entry_digest`** under a genuinely trusted signed Merkle root. By itself it does **not** re-verify the underlying historic Ed25519 observation, v5.8 predecessor hash or manifest authorization. Those v5.8 checks and original signed-entry preservation remain necessary for full provenance.
- The proof generator builds the compact proof from a full local ordered list of `entry_digest` values. The verifier itself needs only the compact proof and independently signed roots. This is a prototype, not a deployed proof-serving transparency service.
- The v5.9 signed Merkle roots are a separate contract; they are not asserted to be the same as the v5.8 linear chain root. A trusted witness must independently validate the mapping from the v5.8 complete audited log to the v5.9 Merkle root before signing or distributing it. The current CI uses synthetic test roots.
- Canonical perfect-subtree covers prove prefix consistency in this **specific v5.9 construction**, not an RFC 6962 consistency proof interchange format. Mixing algorithms, orderings, or tree-size semantics must be refused.
- A malicious issuer who compromises the reviewer signing key or the out-of-band trusted root registry can provide a convincing-looking alternate tree. There is no real-world independent witness quorum, authenticated gossip, public API, quorum agreement or hardware-backed key custody in this Draft.
- CI databases share one PostgreSQL server and administrator, so this does not demonstrate production independent infrastructure or protection against coordinated rollback of both databases and the trusted signing roots.
- Hashes have a 10,000 entry safety limit, and this version does not provide paginated proofs, sparse trees, inclusion lookup service or distributed synchronization.

**No automatic repair, replication, release, merge, install, public rollout or authority escalation. DRAFT / DENY / GO-13 HOLD.**