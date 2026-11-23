# PALACO INDUSTRIE — Signed Startup Evidence Integration v3.6 (DRAFT / HOLD)

## Implementation

`distribution/distribution-startup-interlock.js` now accepts an **optional, explicitly trusted** read-only review evidence bundle as its second argument. It calls `verifyBootstrapDossier()` from v3.5 and reports only whether the two-reviewer cryptographic evidence verified and its canonical digest. The result is `VERIFIED_NON_AUTHORIZING` or `NOT_PROVIDED`; it is deliberately never a runtime capability.

Crucially, `createDistributionStartupInterlock(environment, reviewEvidence)` returns `ingress: null`, `readiness: BLOCKED`, `authorization: DENY`, `go13: HOLD`, `ingressEnabled: false` and all release-related flags false **in every case**. Release-looking environment variables are evaluated separately and cannot change that invariant. Malformed, tampered, stale or revoked review evidence fails closed; raw evidence, signer signatures and environment secrets are not echoed into the returned report.

## Application integration boundary

The existing `server.js` already constructs the v3.4 interlock during startup. In this version it **does not supply a dossier bundle**, because no external independent review store, trusted review-root provisioning, current anchor sequence, or operational checkpoint signer has been configured. Consequently live HTTP distribution endpoints remain unavailable (HTTP 503 after authentication and CSRF). The API is prepared for trusted integration but never accepts evidence from an HTTP body or release environment flag.

## Verification

`tests/distribution-bootstrap-startup-integration.test.js` covers a correctly double-signed dossier, signature tampering, expiry, revocation, absent external sequence, malformed evidence, release-looking environment variables and default closed startup. Existing application auth/CSRF and real PostgreSQL CI suites remain unchanged.

## Non-goals

This is **evidence reporting, not production-ready trust bootstrapping**. A dossier signature cannot prove that its declared hashes match deployed binaries or externally secured witness state; those comparisons and independent origin/transport remain to be established. It does not start or attest an external checkpoint service, automatically provision credentials, create a trusted anchor store, configure release roles, or grant application authorization.

No merge, deployment, publication, installation or production changes. Draft PR #36 and GO-13 HOLD remain in force.
