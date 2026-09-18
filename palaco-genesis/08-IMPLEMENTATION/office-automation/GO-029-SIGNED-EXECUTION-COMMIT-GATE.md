# ∆ GO-029 — SIGNED EXECUTION COMMIT GATE

**Status:** IMPLEMENTED ON BRANCH
**Base:** GO-028 cryptographic provenance + signature binding
**Scope:** final Microsoft Graph execution boundary

## Purpose

GO-029 creates an explicit final gate immediately before external transport.
It requires the request to be cryptographically verifiable before the idempotency claim and transport side effect are allowed.

## Gate order

`EVENT → AUTHORIZATION CHECK → REQUEST BUILD → INTEGRITY CHECK → SIGNATURE/PROVENANCE VERIFY → IDEMPOTENCY CLAIM → TRANSPORT`

Every failure is fail-closed.

## Contract

`execute_signed()` requires:

- a valid PALACO event
- explicit Granted authorization
- a non-empty authorization reference
- a canonical request whose integrity verifies
- a valid Ed25519 signature
- matching provenance reference
- matching SHA-256 digest
- a first-time idempotency claim

Only after these conditions pass may the transport boundary be invoked.

## Constitutional separation

- cryptographic proof does not grant authority
- provenance proves lineage; it does not grant authority
- idempotency prevents duplicate consequential execution
- the execution commit gate does not manufacture authorization
- `CONSENT ≠ AUTHORIZATION`
- `AUTHORIZATION ≠ EXECUTION`
- `ACCESS ≠ AUTHORIZATION`

## Revocation behavior

The safety boundary re-checks authorization immediately before transport. A revoked or expired authorization therefore cannot cross this gate.

## Scope limitation

GO-029 adds no live Microsoft Graph client and stores no bearer token or private key material. The transport remains an explicit external I/O boundary.

## Verification

Tests cover successful signed execution and rejection when the event is changed after signing.

Local Cargo execution is not claimed; CI remains the authoritative compilation/test verification.