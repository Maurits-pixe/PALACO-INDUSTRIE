# ∆ GO-030 — REVOKE PROPAGATION & EXECUTION CANCELLATION

**Status:** DRAFT / implementation branch  
**Branch:** `go-030-revocation-propagation-execution-cancellation`

## Purpose

GO-030 makes **REVOKE a first-class execution control** across queued, pending and retryable Office automation work.

The constitutional invariant is:

> **NO CONTINUED EXECUTION AFTER REVOCATION.**

Revocation is distinct from expiration and remains effective even when a request was signed before the revocation occurred.

## Canonical execution rule

`EVENT → AUTHORIZATION → REQUEST → SIGNATURE/PROVENANCE → REVOKE CHECK → IDEMPOTENCY → FINAL REVOKE CHECK → TRANSPORT`

A valid signature proves integrity and provenance. It does **not** override a later revocation.

## Implemented

### ExecutionControl

`palaco-office-execution-safety` now provides an explicit control record containing:

- execution identity
- trace identity
- revocation state
- scheduled retry count

`revoke()` marks the execution revoked and clears scheduled retries. New retries are rejected.

### Final revocation gate

`revocation_check()` is fail-closed and is evaluated immediately before external transport.

The signed Graph path now exposes `execute_signed_with_control()`, which checks revocation:

1. after signature/provenance verification;
2. after idempotency claim;
3. immediately before transport.

Therefore a request signed before REVOKE cannot continue merely because its signature remains cryptographically valid.

### State separation

The contract preserves the distinction:

- **REVOKED** = explicit withdrawal of authorization/execution permission
- **EXPIRED** = authorization reached its time boundary
- **FAILED** = execution/transport failure
- **COMPLETED** = successful completion

No state is silently converted into another.

## Tests added

- revocation cancels pending/retryable work
- scheduled retries cannot be created after revocation
- revocation remains distinct from expiration
- signed execution is blocked by late revocation

## Constitutional boundaries

- **SIGNATURE ≠ AUTHORIZATION**
- **PROVENANCE ≠ AUTHORIZATION**
- **CONSENT ≠ AUTHORIZATION**
- **AUTHORIZATION ≠ EXECUTION**
- **ACCESS ≠ AUTHORIZATION**
- **EXPIRATION ≠ REVOCATION**
- **REVOKE > pending execution continuation**

## Non-goals

GO-030 does not introduce:

- live Microsoft Graph credentials
- token storage
- automatic authorization
- automatic governance consent
- a background worker
- hidden retry execution
- external side effects

The transport remains an explicit boundary.

## Verification status

The changes are committed to the GO-030 branch. Local Cargo tests have **not** been run through the GitHub connector; CI execution must be verified separately before merge.

