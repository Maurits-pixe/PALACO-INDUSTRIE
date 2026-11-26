# PALACO INDUSTRIE — Guarded Proof Verification Gateway v6.1

**Status:** DRAFT / DENY / GO-13 HOLD. No merge, installation, public endpoint, production rollout or activation.

## Gateway boundary

`distribution/manifest-proof-gateway-v6.1.js` is an **opt-in, in-process request-handler adapter**, not a listening HTTP endpoint. It wraps only the independent v6.0 read-only proof verifier; it does not hold a signing key, connect to the proof issuer or expose direct database reads or writes. The only supported request types are `inclusion` and `consistency` under one exact versioned schema. It requires a scoped namespace, an 8–64-character request ID and a plain object envelope. Unknown top-level fields, cross-namespace requests, malformed bodies and request JSON larger than 4,096 bytes are blocked.

An injected trusted monotone millisecond clock controls a per-process quota of 20 requests per 60 seconds by default (configurable to 1–100). The gateway records accepted request IDs in process memory to reject repeated IDs; a one-request execution guard prevents unbounded concurrent checks. These limits **are not** durable, distributed or a global throttle across processes. Busy concurrent requests are rejected immediately and **are not audited in this version**; this residual audit gap must be closed before network exposure. A backward clock jump blocks. An operator must supply an independently authorized identity and a robust persistent rate-limiter before offering a network interface.

Successful cryptographic proof checks still return only `PROOF_GATEWAY_VERIFIED_NON_AUTHORIZING` with `authorization=DENY`, `go13=HOLD` and all `may*` flags false. The gateway deliberately never forwards privileged verifier internals. Cryptographic failures are translated to generic `PROOF_GATEWAY_PROOF_REJECTED`, avoiding accidental disclosure of independent roots, trust keys, raw SQL errors or detailed mismatches.

## Append-only audit

The gateway requires an injected `auditAppend` function. After each sequential request, it builds a compact record containing only the namespace, fixed principal ID, request ID, SHA-256 digest of the request, event time, readiness/finding and DENY/HOLD status. It never writes raw proof bodies, secrets or private keys into the record. A positive response is returned **only if auditAppend reports durable success**. If the audit backend fails or rejects the event, the gateway fails closed as `PROOF_GATEWAY_AUDIT_UNAVAILABLE`. Storage proof is limited to the truthfulness of the supplied adapter.

`distribution/sql/proof-verification-audit-v6.1.sql` defines an immutable CI PostgreSQL audit log with role-scoped namespace access and ordinary UPDATE, DELETE and TRUNCATE denial. Privileged database owners can still reconstruct this schema; independent audit custody, cryptographically chained audit receipts and production role separation are not implemented.

## Tests

`tests/distribution-manifest-proof-gateway-v6.1.test.js` includes six groups: valid inclusion/consistency, malformed or oversized requests and replay, rate quotas, clock/audit/provider failures, parallel load rejection, abort and authorization invariants.

`tests/postgres-manifest-proof-gateway-v6.1.test.js` provisions one disposable PostgreSQL 17 CI database and a restricted INSERT/SELECT audit writer. It persists one successful verification plus replay and rate-limit denials, verifies immutable DENY/HOLD records, rejects ordinary UPDATE/DELETE/TRUNCATE/trigger alterations and blocks a fresh request following an actual database connection shutdown.

## Required before any external service

- Add an independently operated HTTP/gRPC ingress with authenticated principal, TLS/mTLS, origin and request-size limits enforced **before** JSON parsing, timeouts, shared durable rate-limit and replay ledgers.
- Close the concurrent `BUSY` audit gap, ensure sustained audit capacity, and add tamper-evident audit-chain checkpoints verified by an independent custodian.
- Add signed, independently retained evidence of root pinning and actual organizational and physical separation of proof issuer, verifier, audit and trust authorities. Current CI logical databases share one PostgreSQL server/admin.
- Run full v5.8 provenance verification and v5.9 Merkle consistency checks as separate trusted prerequisites; compact proofs alone are not end-to-end issuance or release authority.

**No public port is bound. `main` untouched. No deployment, publication, merges, privileged key operation or automatic repair.**