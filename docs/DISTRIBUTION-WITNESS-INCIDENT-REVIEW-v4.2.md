# PALACO INDUSTRIE — Forensic Witness Incident Review v4.2 (DRAFT / HOLD)

## Design

`distribution/witness-incident-review.js` creates a **read-only cryptographic verification primitive** for conflicting primary and secondary authority witness observations. An incident record binds namespace, incident ID, independent incident sequence, preceding incident digest, observation and expiry timestamps, both witness revision/digest pairs, and mandatory `authorization=DENY`, `go13=HOLD`, `recommendedAction=QUARANTINE_NO_SYNC`.

Two different, externally pinned and non-revoked Ed25519 reviewer identities must sign the exact canonical bytes. The independently held incident sequence/digest is an explicit input; stale/replayed sequence, invalid signatures, duplicate humans, revoked keys, oversized lifetime and any instruction to synchronize or release are rejected. A cryptographically valid review returns `INCIDENT_REVIEW_VERIFIED_NON_AUTHORIZING` only — **not authority to reconcile, restore or deploy**.

`verifyLiveWitnessIncident()` additionally re-reads **both** witness heads, checks they are distinct and exactly match the signed snapshot, and refuses if a witness is offline, heads changed or a request was aborted. The diagnostic `INCIDENT_LIVE_DIVERGENCE_VERIFIED_NON_AUTHORIZING` is observational: `maySynchronize=false`, `mayReconcile=false`, `mayRestore=false`, `mayAdvance=false`, `mayRotate=false`, `mayInstall=false`, `mayPublish=false`.

## Test coverage

`tests/distribution-witness-incident-review.test.js` exercises independent quorum, signed tampering, malicious repair instructions, historical replay, expiry, revocation, missing witness and changing evidence. The existing disposable live PostgreSQL two-database test now signs a forensic incident corresponding to restored primary revision 10 versus secondary revision 11, verifies its exact live match, then changes the primary head and proves the former signed incident is stale. No production records or roles are modified.

## Trust boundary and limitations

- This is **incident verification**, not an incident *resolver*. No update, merge, repair, key issuance or automatic synchronization operation is exposed.
- Independent incident sequence/digest and pinned reviewer roots must come from separately secured, durable services. A caller that supplies its own self-signed roots and rollback anchor can fabricate a plausible incident. The verifier does not establish real-world operator identity or infrastructure isolation.
- Live comparisons are two sequential remote reads, not an atomic distributed snapshot. Concurrent changes can occur after verification. Evidence therefore cannot authorize writes even when valid.
- The CI uses two databases in a single PostgreSQL service with shared administrators. This is a controlled restore simulation, **not** production-grade independent witnesses.
- The existing HTTP distribution endpoints remain disabled (`ingress:null`). The new module is not mounted as an HTTP endpoint and never changes GO-13 authority.

## Safe next steps

An independently controlled append-only incident ledger with monotone incident sequence, explicit human incident adjudication and immutable archival evidence could support later review. Any actual repair procedure requires an entirely separate authorization and audited operational design, not a new flag on this verification module.

**Governance:** `DENY / GO-13 HOLD`; Draft PR #36, no merge, deployment, publication, installation or production database change.