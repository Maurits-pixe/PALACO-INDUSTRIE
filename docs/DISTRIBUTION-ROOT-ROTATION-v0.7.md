# PALACO INDUSTRIE — Dual-Root Rotation Preflight v0.7 (DRAFT / HOLD)

A read-only gate for **future** root-key rotation. It verifies an independently old-root-signed checkpoint plus separate signatures from an old pinned root and a proposed new root on a domain-separated transition payload. The payload commits to checkpoint sequence, prior digest, checkpoint digest, and both sorted root-set fingerprints.

Exports from distribution/root-rotation.js:
- rotationPayload(proposal, oldRoots, newRoots)
- assessRootRotation(proposal, checkpoint, oldRoots, newRoots, oldCheckpointEndorsement, oldRotationEndorsement, newRotationEndorsement)

Old roots MUST be independently pinned in a protected local trust configuration; the caller MUST NOT derive them from an untrusted proposal, snapshot or downloaded package. The new-root signature proves possession of its private key only; the new root's authority, provenance, governance approval, quorum, expiry, compromise handling and key replacement policy remain to be implemented separately.

A passing preflight is never a key installation, approval or release authorization. Even for passing inputs, output is authorization DENY, GO-13 HOLD, mayRotate false, mayPublish false, mayInstall false. No database or filesystem is changed.

A production flow requires a dedicated atomic transaction combining independently approved root pin replacement, rollback-resistant anchor advancement and audited governance evidence. Root sets containing overlapping key IDs are deliberately prohibited in this draft.

Run: node --test tests/distribution-root-rotation.test.js. This module should not be treated as a complete TUF-style update framework or as recovery from a compromised old root.
