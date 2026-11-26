# PALACO INDUSTRIE — Trust Continuity v0.4 (DRAFT / HOLD)

This update adds a **read-only, sequential SHA-256 checkpoint continuity check** for a caller-supplied public-key registry. It composes with existing Ed25519 manifest and actual package-byte verification.

## Contracts

- `digestSnapshot(snapshot)`: deterministic SHA-256 of the validated trust-record list, sorted by unique key ID. Covers key ID, PEM text, enabled and revoked flags. Returns `null` for malformed or duplicate entries.
- `assessTrustContinuity(snapshot, checkpoint, anchor)`: expects a caller-provided **durable, authenticated** anchor `{sequence, digest}` and candidate checkpoint `{schemaVersion:"palaco.distribution.checkpoint.v1", sequence, previousDigest, digest}`. Requires exactly `anchor.sequence+1`, matching predecessor digest, and matching registry digest. No state updates.
- `verifyDistributionWithContinuity(manifest, bytes, envelope, snapshot, checkpoint, anchor)`: combines the continuity check with v0.3 signed artifact verification.

## Explicit security limits

**This is NOT a complete anti-rollback system**. A caller must independently authenticate the checkpoint's issuer, obtain a revocation-complete registry from a trusted source, persist the last accepted anchor in rollback-resistant storage, and advance that anchor atomically only after successful verification. The implementation has no authenticated root, trusted clock, independent authority proof, persistent state, or installation side effects. A forged checkpoint and forged snapshot can match each other cryptographically without being trustworthy. A vulnerable caller can pass an old anchor and old registry and defeat freshness.

No release capability exists. All outputs force `authorization=DENY`, `go13=HOLD`, `mayPublish=false`, `mayInstall=false`.

Run `node --test tests/distribution-trust-continuity.test.js`; do not promote without independent review and environment-specific trust anchoring.
