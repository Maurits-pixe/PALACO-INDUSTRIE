# PALACO INDUSTRIE — Signed Authority Receipt v1.1 (DRAFT / HOLD)

The read-only module `distribution/authority-receipt.js` verifies an Ed25519-signed authority-state response against independently pinned public keys. It replaces reliance on the unverified `authenticated:true` claim in the v1.0 preflight **for new callers using this API**; the older v1.0 API remains unchanged and MUST NOT be treated as cryptographically authenticated.

## Contract

- `authorityReceiptPayload(state)`: canonical, domain-separated newline-terminated UTF-8 bytes for `{schemaVersion:"palaco.distribution.authority-state.v1",namespace,sequence,digest,challenge}`.
- `verifyAuthorityReceipt(namespace,state,endorsement,pinnedRoots,challenge,minimumSequence)`: checks the exact verifier challenge, Ed25519 signature, active independently pinned root, and a separately protected minimum sequence.
- `assessAuthenticatedRecovery(namespace,restored,state,endorsement,pinnedRoots,challenge,minimumSequence)`: requires the restored namespace, sequence and digest to match the authenticated state.

## Security boundary

A verifier must generate a fresh, unpredictable cryptographic challenge for every request using secure randomness and must never reuse it. The test suite uses deterministic test values only. The minimum sequence MUST come from independently rollback-resistant storage; the verifier cannot prove it is current. A trusted root MUST be provisioned via independently authenticated configuration; neither a remote reply nor the restored database may supply the root. These checks prove authenticity of a response under the pinned key, not that the remote authority is correctly implemented or stores checkpoints durably.

This module contains no transport, authenticated remote authority service, durable monotonic storage, caller permission evaluation, trusted time, hardware anti-rollback, or release actions. It DOES NOT advance an anchor or restore a database. In every state: `authorization=DENY`, `go13=HOLD`, `mayAdvance=false`, `mayRestore=false`, `mayRotate=false`, `mayPublish=false`, `mayInstall=false`.

Local test command: `node --test tests/distribution-authority-receipt.test.js`. Eight tests passed locally on Node v22.16.0. GitHub CI must independently confirm the branch.
