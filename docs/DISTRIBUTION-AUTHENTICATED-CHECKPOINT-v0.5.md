# PALACO INDUSTRIE — Authenticated Checkpoint Gate v0.5 (DRAFT)

This read-only module requires an **independent Ed25519 root signature** over the trust checkpoint in addition to manifest validation, package-byte hashing, artifact signing, and sequential continuity.

## Integration

\`distribution/authenticated-checkpoint.js\` exports:

- \`checkpointSigningPayload(checkpoint)\`: deterministic domain-separated UTF-8 encoding for signed checkpoint objects.
- \`verifyCheckpointAuthority(checkpoint, endorsement, pinnedRoots)\`: verifies checkpoint authenticity against caller-pinned Ed25519 public keys.
- \`verifyAuthenticatedDistribution(manifest, bytes, artifactSignature, snapshot, checkpoint, anchor, endorsement, pinnedRoots)\`: combines all checks and blocks on any failure.

The endorsement is \`{ algorithm: "Ed25519", keyId: "offline-root-test", signature: "<base64>" }\`. The trusted root entries are \`{keyId, enabled: true, revoked: false, publicKeyPem}\`. Test keys are generated ephemerally by the regression suite; **no deployment trust roots are shipped here**.

Signing bytes are LF-separated UTF-8 lines (including final newline): \`PALACO-INDUSTRIE-TRUST-CHECKPOINT-V1\`, \`schemaVersion\`, decimal \`sequence\`, \`previousDigest\`, \`digest\`. Validate the checkpoint before producing signing bytes.

## Mandatory operational boundary

Pinned roots must be authenticated independently of downloaded packages, snapshots and checkpoint endorsements; they MUST NOT be taken from the registry under verification. The anchor must come from rollback-resistant durable storage and must be updated atomically by an independently authorized component. This library neither persists the anchor nor enforces freshness against a trusted clock. It does not establish root rotation, quorum, expiry, recovery, release approval, or an actual installer.

Output states are diagnostic only. Even when all checks pass: **authorization DENY, GO-13 HOLD, mayPublish false, mayInstall false**. No external side effects.

Run \`node --test tests/distribution-authenticated-checkpoint.test.js\` and complete independent security review before considering any release workflows.
