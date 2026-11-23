# PALACO INDUSTRIE — Signed Bootstrap Review Dossier v3.5 (DRAFT / HOLD)

## Purpose

The new `distribution/bootstrap-review-dossier.js` verifies a **read-only**, domain-separated bootstrap evidence dossier. It **does not** activate, provision, deploy or create an independent checkpoint service. The HTTP startup interlock from v3.4 remains deliberately closed.

## Evidence contract

The v1 canonical payload cryptographically binds namespace, an externally sequenced dossier number, issue/expiry timestamps, SHA-256 digests for source, checkpoint, independent anchor, PostgreSQL schema and pinned roots, plus the immutable governance assertions `authorization=DENY` and `go13=HOLD`.

Verification requires two valid Ed25519 endorsements from **different pinned key IDs and different reviewer identities**, with both roots enabled and explicitly not revoked. A caller-provided trusted minimum sequence prevents a signed older review dossier from passing. A restricted lifetime prevents indefinite replay. Missing anchors, future or expired attestations, tampered fields, duplicate reviewers and invalid signatures fail closed.

**Passing signatures do not imply operational trust.** The verifier always returns `readiness=BLOCKED`, `authorization=DENY`, `go13=HOLD`, `ingressEnabled=false` and release-related flags false. A passing evidence check returns `BOOTSTRAP_EVIDENCE_VERIFIED_NO_RELEASE_AUTHORITY` and the SHA-256 dossier payload digest only.

## Required independent infrastructure (NOT installed)

- Independently owned and provisioned reviewer public-key registry with reviewer-identity separation and revocation controls
- Rooted and durable anti-rollback sequence/anchor outside the PostgreSQL backup and signer trust domains
- Verified source/artefact provenance, checkpoint witness, key custody and independently operated signing process
- A reviewed operator process for time sources, review expiry, incident recovery and key rotation
- Mandatory integration tests against real, separately administered services and audited HTTP session policy

The v3.5 module is an **offline verification primitive**; it does not automatically load environment variables, touch private data or issue network requests. It is not connected to `server.js` as an enablement mechanism. Reviewers and trusted roots in unit tests are freshly generated, not production credentials.

Draft PR #36 only: **no merge, publication, installation, release or production deployment**. GO-13 HOLD is preserved.
