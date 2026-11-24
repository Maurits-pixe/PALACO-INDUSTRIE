# PALACO INDUSTRIE — Partial Evidence Transfer Diagnostics v5.2 (DRAFT / HOLD)

## Read-only classifier

`distribution/evidence-transfer-reconciliation-v5.2.js` compares two independent query providers: the full historic signed-evidence source and its externally stored v5.0/v5.1 SHA-256 high-water root. It verifies the full metadata succession, full signed evidence commitments, **every historical Ed25519 issuer and recipient signature**, and the signed adjacency of witness revisions before classifying head divergence.

`MATCHED_NON_AUTHORIZING` means that the source and external full-evidence root match, and that a receipt metadata row exists for the external head when it is later than the pinned starting root. `SOURCE_AHEAD_HOLD` means the local signed source has **exactly one** extra verified receipt and the external root matches the exact signed prefix: a partially completed handoff, not permission to replay, recover or advance. A missing root, missing receipt, invalid signature, offline provider, fork/digest mismatch, archive rollback, source lag or multiple unanchored steps is `BLOCKED`.

All results expose immutable `authorization=DENY`, `go13=HOLD`, and false for `mayAdvance`, `mayRestore`, `mayReconcile`, `maySynchronize`, `mayInstall` and `mayPublish`. No SQL write call, recovery endpoint, retry scheduler or automated repair path is exposed.

## Verification

`tests/distribution-evidence-transfer-reconciliation-v5.2.test.js` exercises six categories: matched state, a single source-ahead partial transfer, restored primary, independent fork, multiple unaudited advances, unavailable/missing receipt or storage, historical signature tampering, and abort/invalid adapter construction. The disposable PostgreSQL v5.1 live integration has been augmented to inspect **before** an external receipt (source ahead), **after** a correctly received external transfer (matched), and **after** privileged source schema destruction (blocked). GitHub Actions directly executes the combined live integration.

## Boundaries and residual risk

- A v5.1 `transfer_receipts` row contains nonce, recipient ID, handoff digest and signature JSON but not the full signed handoff and signed receipt payloads. The v5.2 observer checks **presence and shape only** of the anchor receipt row; it cannot independently cryptographically reverify a historical external transfer from that row alone. An independently archived complete v5.1 transfer dossier and per-sequence key history are needed to close this gap.
- The source and anchor are read separately without a distributed atomic snapshot; concurrent honest writes can produce a transient `SOURCE_AHEAD_HOLD` or `BLOCKED`. This is intentionally non-authorizing. It is not evidence of operator malice by itself.
- The genesis starting sequence is operator-pinned and assumed independently trusted. No records before it are evaluated. No more than 10,000 entries are accepted per pass.
- Both CI databases remain under a single PostgreSQL server and administrator. This does not demonstrate independent production custody or coordinated-rollback resistance.
- No installation, release, migration, HTTP ingress, production credentials, merge or autonomous recovery is performed.

**Governance: Draft PR #36; `DENY / GO-13 HOLD` regardless of diagnostics.**