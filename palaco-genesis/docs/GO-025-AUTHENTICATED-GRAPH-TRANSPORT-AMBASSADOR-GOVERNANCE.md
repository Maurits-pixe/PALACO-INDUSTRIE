# GO-025 — AUTHENTICATED GRAPH TRANSPORT + AMBASSADOR GOVERNANCE

## Status

**DRAFT / CONTRACT ONLY**

GO-025 extends GO-024 without performing a live Microsoft Graph write.

## Constitutional chain

`IDENTITY → PROVENANCE → EVIDENCE → DECISION → RAAD VAN 7 → CONSENT/VETO → AUTHORIZATION → EXECUTION COMMIT → SAFETY RE-CHECK → IDEMPOTENCY → AUTHENTICATED GRAPH TRANSPORT → MICROSOFT GRAPH → EXECUTION RECEIPT → TRACE`

## Council of Seven

The governance crate models exactly seven attributable seats:

1. Architect
2. Ambassador 2
3. Ambassador 3
4. Ambassador 4
5. Ambassador 5
6. Ambassador 6
7. Ambassador 7

Thresholds:

- **5 approvals** = First Consent
- **7 approvals** = Final Grant
- **valid veto** = Blocked by Veto

Every decision requires provenance and scope references.

Council consent is governance state only. It does **not** directly mutate an Office event's authorization or execute an external action.

## Authentication boundary

GO-025 introduces an opaque `AuthenticatedSession` reference and a `GraphAuthenticator` trait.

Raw bearer tokens are deliberately outside the contract. Credential acquisition, storage and refresh remain implementation responsibilities.

Therefore:

**ACCESS ≠ AUTHORIZATION**

An authenticated Microsoft session permits transport authentication; it does not itself authorize a PALACO operation.

## Execution safety

The existing GO-024 order remains mandatory:

1. Validate event.
2. Verify authorization and authorization reference.
3. Verify execution is Started.
4. Validate action boundary.
5. Claim idempotency.
6. Authenticate the transport.
7. Send the bounded request.
8. Convert the response into an execution receipt.
9. Preserve traceability.

No live Graph credentials or network client are introduced by GO-025.

## Non-goals

- No token storage.
- No OAuth implementation.
- No Microsoft account mutation.
- No automatic authorization from authentication.
- No invented task payload.
- No bypass around REVOKE, idempotency, or execution commit.

## Canonical invariant

> **AUTHENTICATION PROVES ACCESS TO THE TRANSPORT.**
>
> **AUTHORIZATION PROVES PERMISSION TO EXECUTE THE PALACO ACTION.**

They are separate constitutional facts and must remain separately traceable.
