# PALACO INDUSTRIE — Signed Distribution Verification v0.3 (DRAFT)

This draft composes three **read-only** checks: manifest schema, SHA-256 over supplied bytes, and Ed25519 verification of a deterministic, versioned UTF-8 manifest representation.

## API

`verifySignedDistribution(manifest, bytes, envelope, trustSnapshot)` is exported by `distribution/signed-verifier.js`. `signedManifestPayload(manifest)` defines the precise serialization used when signing.

The envelope is `{ "algorithm": "Ed25519", "keyId": "key-id", "signature": "<canonical-base64-64-byte-signature>" }`.

The caller supplies the trusted key snapshot:
```json
{
  "schemaVersion": "palaco.distribution.trust.v1",
  "complete": true,
  "revocationsChecked": true,
  "keys": [{
    "keyId": "key-id",
    "enabled": true,
    "revoked": false,
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----..."
  }]
}
```

`complete` and `revocationsChecked` are **caller assertions, not independent proof**. The verifier cannot determine if the snapshot is authentic, fresh, rollback-resistant, or complete. The caller must obtain it through a separately verified, trusted channel and block on any freshness, authentication or revocation uncertainty. Never trust a self-declared snapshot from an untrusted package. No production trust root is embedded.

Signing payload: UTF-8 lines, ordered as `PALACO-INDUSTRIE-DISTRIBUTION-V1`, `schemaVersion`, `appId`, `version`, `artifact`, `sha256`, decimal `sizeBytes`, `channel`, `authorization`, `go13`, plus a terminal newline. Only sign validated manifests. The test suite uses ephemeral test keys.

Failure of any check produces `readiness=BLOCKED`. Passing checks produce `SIGNED_BYTES_MATCH`, **not** authorization. In every state: `authorization=DENY`, `go13=HOLD`, `mayPublish=false`, `mayInstall=false`. No signing keys are generated or stored by production code; no installer, publisher or deployment action exists.

Run `node --test tests/distribution-signed-verifier.test.js`. Further work: authenticated trust-root delivery, freshness and rollback protection, transparent provenance, release approvals, and independent human-controlled authorization.
