# PALACO INDUSTRIE — Externally Anchored Signed Checkpoint v3.0 (DRAFT / HOLD)

## Objective

Add cryptographic evidence for the monotonic PostgreSQL witness, and detect a restored PostgreSQL state **when an independently held, more recent checkpoint and chain anchor remain available**.

## Components

- `distribution/continuity-checkpoint.js`: canonical domain-separated checkpoint payload, SHA-256 digest, Ed25519 verification, pinned unrevoked root, fresh nonce, externally supplied exact sequence and predecessor digest plus anchored epoch/clock minima.
- `distribution/postgres-checkpoint-verifier.js`: validates that a signed, externally anchored checkpoint matches exactly one live PostgreSQL high-watermark row. Missing rows, mismatched values and database errors return `BLOCKED / DENY / HOLD`.
- `tests/distribution-continuity-checkpoint.test.js`: nine tests for authentic proofs, signatures, altered fields, nonce replay, rollback, previous-digest linkage and missing anchors.
- `tests/postgres-checkpoint-verification.test.js`: live PostgreSQL CI test. First confirms valid checkpoint matching the database. Then a privileged test account deliberately rolls back the database row and demonstrates that the still-anchored signed checkpoint detects the mismatch. A separately re-signed historical checkpoint is also blocked by the independent sequence anchor.

## Security contract and deliberate limitations

Checkpoint signatures alone **do not prevent rollback**. A malicious actor can replay a historical signed checkpoint if the verifier does not have independent knowledge of a newer chain head. Therefore the caller MUST supply `minimumSequence` and `priorDigest` obtained from a trust domain outside the PostgreSQL backup/restore path and outside the signing service's control. Pinned root keys must likewise be independently provisioned. The verifier does NOT create, distribute or persist such anchors. The code does not provide a signing or witness service, external transparency log, HSM/KMS policy, multi-party consensus, protected backup system, or durable anchor storage.

The checkpoint verifier is a **separate verification API**, not yet a mandatory path in the challenge registry's `issue` or `consume`. It cannot be represented as a production-enforced gate until independently anchored fresh evidence is plumbed through an authenticated runtime protocol and reviewed. The live CI tests use ephemeral generated signing keys and an in-memory test anchor; they do not establish real-world independence from a privileged administrator.

No production resource was modified. PR #36 stays Draft; authorization `DENY`, GO-13 `HOLD`; no merge, release, publication, install or deployment.
