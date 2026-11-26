# PALACO INDUSTRIE — Distribution Manifest Gate v0.1 (DRAFT)

This is a **read-only metadata assessment**, not an artifact verifier, installer, signer, release approval, or deployment mechanism.

## Inputs

The local CommonJS function `assessDistributionManifest(manifest)` accepts:

```json
{
  "schemaVersion": "palaco.distribution.v1",
  "appId": "palaco.one",
  "version": "0.1.0",
  "artifact": "palaco-one.zip",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sizeBytes": 1024,
  "channel": "draft",
  "authorization": "DENY",
  "go13": "HOLD"
}
```

The digest is only format-checked: it is **not** calculated against package bytes. No signature, provenance, vulnerability, dependency or runtime verification occurs. The artifact field must be a plain filename (no directories or URL).

## Result and authority boundary

- Valid metadata: `readiness=MANIFEST_VALID`; invalid metadata: `readiness=BLOCKED` with diagnostic codes.
- Always: `authorization=DENY`, `go13=HOLD`, `mayPublish=false`, `mayInstall=false`.
- A metadata-valid result can never grant release permission, override revocation, bypass GO-13 or trigger external side effects.
- This module deliberately has no I/O and does not alter existing authentication, deployments or repository publishing.

## Regression tests

`node --test tests/distribution-manifest-gate.test.js`

Before any future promotion, add actual byte-hash verification, trusted signatures, independent authorization, revocation/freshness checks, and a separate human-controlled release gate.
