# PALACO INDUSTRIE — Roster Authority Key Rotation v3.8 (DRAFT / HOLD)

## Scope

`distribution/roster-authority-rotation.js` adds a **read-only, cryptographically authenticated** rollover contract for the authority that signs reviewer-register transitions. No keys are provisioned, revoked operationally, installed or deployed by this module.

Each proposed transition binds a canonical ordered authority-key history, sequential revision, predecessor digest, old/new key IDs and digest of the proposed next history. Exactly one authority key may be active in each history. A successful transition requires the old active key to become revoked, exactly one **new** key to become active, and every earlier key, ID and history record to be retained unchanged.

The same domain-separated rotation payload must be signed by both the outgoing and incoming Ed25519 authority keys **and two distinct, externally pinned reviewers**. Reviewers must have distinct human IDs and distinct public keys, be explicitly enabled/not revoked, and use neither outgoing nor incoming authority keys. Invalid key data, duplicate pinned reviewers, missing signatures, absent historical anchors, skipped revisions and rollback attempts fail closed.

`verifyRotationBoundReviewerRosterTransition()` is an explicit stronger variant of the existing reviewer roster verifier. It derives the allowed new roster signing key **only** from a successfully verified rotation proof. `verifyRosterBoundBootstrapDossier()` can require that rotated-authority proof when trusted startup code supplies `rosterEvidence.authorityRotation`. This pathway is diagnostic-only; the v3.4 startup interlock continues to return `ingress:null` and the HTTP distribution endpoints remain disabled.

## Independent-trust assumptions and limitations

- The old authority-history revision/digest and independent reviewer public keys MUST be pinned outside the authority's restore and signing domains. A malicious caller that controls these purported trust anchors can forge a self-consistent story.
- Ed25519 verifies key possession and content integrity, **not legal personhood**, independent consent or operator separation. Reviewer identity enrollment, revocation distribution, durable ledger persistence, expiry, incident response, and hardware key custody need separately approved controls.
- This design rejects unannounced substitution of the current authority, and supports an explicit rollover as non-authorizing evidence. It is **not** a key-rotation executor and cannot grant a GO-13 release.
- Existing simpler verifier routes remain for compatibility. The stricter rotation-bound route is opt-in and no production service has been migrated.

## Verification

Unit regressions cover old/new co-signatures, two distinct independently pinned reviewers, review revocation, rollback, skipped/missing history, key substitution, stale anchor, wrong namespace, attempted reuse of a retired authority and invalid signatures. The existing live PostgreSQL integration continues to run in a disposable GitHub Actions service.

All evidence paths remain `authorization=DENY`, `go13=HOLD`, `mayRotate=false`, `mayPublish=false`. Draft PR #36: no merge, installation, publication or deployment.
