# GO-027 — CANONICAL REQUEST INTEGRITY

## Status
**DRAFT / CONTRACT**

GO-027 adds a cryptographic integrity boundary between the canonical PALACO action and Microsoft Graph transport.

### Contract

Every `GraphRequest` carries a SHA-256 `integrity_hash` derived from:

`method | path | body | event_id | trace_id | authorization_reference | idempotency_key`

The hash is recomputed and verified immediately before the transport boundary.

### Canonical rule

> WHAT IS BOUND SHALL BE EXACTLY WHAT IS TRANSPORTED.

A mutation of path, body, event identity, trace identity, authorization reference or idempotency key invalidates the request integrity check.

### Governance relationship

The Council of Seven remains upstream governance:

`RAAD VAN 7 → CONSENT/VETO → AUTHORIZATION → EXECUTION`

Council consent does not become a cryptographic credential and authentication does not become authorization.

### Safety

`VALIDATE → AUTHORIZATION → EXECUTION COMMIT → SAFETY → IDEMPOTENCY → REQUEST INTEGRITY → AUTHENTICATED TRANSPORT → GRAPH → RECEIPT → TRACE`

No live Microsoft Graph write or credential storage is introduced by GO-027.
