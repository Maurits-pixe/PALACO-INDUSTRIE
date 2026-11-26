# PALACO INDUSTRIE — Dual-Observer Signed Manifest Publication Views v5.7

**Status: Draft PR #36 / DENY / GO-13 HOLD.** No release, merge, production publication or deployment.

## Purpose

Detect a signed **split-view** in the v5.6 third-witness key-manifest succession, where two separately trusted observers attest different manifest digests or different predecessor digests for the **same namespace and rotation number**.

## Implementation

`distribution/manifest-publication-views-v5.7.js` defines canonical, domain-separated Ed25519 publication-view bytes: namespace, rotation number, manifest digest, predecessor digest, observer ID, observation timestamp and `DENY/HOLD` non-authorizing purpose. `createManifestPublicationViewVerifier` requires two different query adapters, independently pinned observer signing roots and independently pinned old/new manifest digests. The verifier demands exactly one record from each observer, verifies both historic Ed25519 signatures, enforces distinct observer IDs, key IDs and public keys, then compares the manifest and predecessor digests. Two different but individually valid signed views are flagged `PUBLICATION_VIEW_SIGNED_SPLIT_VIEW_DETECTED` and **blocked**. An agreement on an unpinned manifest is also blocked. Missing, ambiguous, unavailable or tampered observations fail closed.

`distribution/sql/manifest-publication-views-v5.7.sql` provisions an append-only, one-record-per-namespace-and-rotation store intended to be deployed **separately per observer**. PostgreSQL guards against ordinary UPDATE, DELETE and TRUNCATE. This Draft schema is not a production migration and cannot verify signatures inside PostgreSQL; a trusted signing/ingestion service and restricted database privileges are prerequisites.

## Verification

`tests/distribution-manifest-publication-views-v5.7.test.js` includes six test groups covering two valid matching signed views, two authentic conflicting views, forgery and revoked/duplicated observer keys, missing or offline observer, invalid rotation/purpose, and aborted verification.

`tests/postgres-manifest-publication-views-v5.7.test.js` provisions two separate **logical** PostgreSQL 17 CI databases. Different Ed25519 keys sign different manifest digests for the same rotation; the comparison detects and blocks split-view. The test rejects UPDATE, DELETE, TRUNCATE and duplicate INSERT and proves that privileged removal/recreation of one observer table results in BLOCKED, never implicit approval.

## Limits and threat model

- Both CI databases share one PostgreSQL host/administrator, so physical and organizational observer independence is **not demonstrated**. A coordinated attacker able to replace both witnesses and their pinned roots defeats the prototype.
- This is a read-only **comparison verifier**, not an actual globally available or independently synchronized manifest publication service. The verifier requires two records; it does not establish global anti-equivocation, quorum consensus, gossip, independent time attestation or network transparency.
- No automatic writes are exposed. The `publication` concept denotes **evidence of an observer's view**, not production publication of keys. Real distribution and activation of updated trust manifests remain blocked.
- The verifier proves possession of independently pinned Ed25519 keys and matching signed bytes. True independence of operator identity, revocation policy and secure key custody must be established out of band.
- Two observations may have been made at different instants; transient divergence is deliberately a HOLD condition. The verifier does not auto-reconcile or repair.
- Key rotation remains separately validated by v5.6 and the third-witness floor remains independently checked by v5.5. A v5.7 match does not bypass either prerequisite.

**No merge, deploy, key activation, installation, synchronization or release. `authorization=DENY`, `go13=HOLD` permanently in this Draft.**