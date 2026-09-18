# ∆ GO-028 — CRYPTOGRAPHIC PROVENANCE + SIGNATURE BINDING

**Status:** IMPLEMENTED ON BRANCH
**Base:** GO-027 canonical request integrity
**Scope:** Microsoft Graph request boundary
**Constitutional anchor:** PVB-011

## Canonical rule

> WHAT IS SIGNED SHALL BE EXACTLY WHAT IS VERIFIED.

GO-028 replaces the GO-027 delimiter-based integrity representation with one explicit canonical byte encoder. The same byte sequence is used for SHA-256 binding and Ed25519 signature verification.

## Canonical encoding

The signed representation contains, in fixed order:

1. HTTP method
2. Graph path
3. request body
4. event ID
5. trace ID
6. authorization reference
7. idempotency key
8. source provenance reference
9. evidence reference
10. provenance reference

Every field is encoded as a big-endian u64 byte length followed by the exact UTF-8 bytes. No debug formatting, implicit map ordering, query-string reconstruction, or semantic re-serialization is permitted.

## Cryptographic contract

- **Algorithm:** Ed25519
- **Digest:** SHA-256 of the exact canonical bytes
- **Signature:** Ed25519 over those exact canonical bytes
- **Key reference:** opaque identifier only; private key material is not stored in the request contract
- **Provenance reference:** included in the signed material and checked again during verification

The public API exposes:

- canonical_request_bytes()
- canonical_request_sha256()
- sign_request()
- verify_request_signature()

## Constitutional separation

Cryptography does **not** create authority.

- Signature → authenticity/integrity of the signed request
- Provenance / Watermerk reference → lineage
- Authorization → permission to execute
- Execution commit → permission to cross the side-effect boundary
- Council consent → governance decision; CONSENT ≠ AUTHORIZATION
- Repository/session access → access only; ACCESS ≠ AUTHORIZATION

Therefore:

**SIGNATURE ≠ AUTHORIZATION**
**PROVENANCE ≠ AUTHORIZATION**
**CONSENT ≠ AUTHORIZATION**
**AUTHORIZATION ≠ EXECUTION**

## Fail-closed behavior

Verification rejects:

- empty key/provenance references
- unsupported algorithm identifiers
- provenance mismatch
- digest mismatch
- malformed public keys
- malformed or invalid signatures
- request tampering after signing

No external Graph write is introduced by GO-028. Credentials and bearer tokens are not stored.

## Verification coverage

Tests cover:

- exact sign/verify equivalence
- request tampering failure
- provenance binding
- algorithm identification

Local Cargo execution is **not claimed** by this change; CI should perform the authoritative build/test verification.