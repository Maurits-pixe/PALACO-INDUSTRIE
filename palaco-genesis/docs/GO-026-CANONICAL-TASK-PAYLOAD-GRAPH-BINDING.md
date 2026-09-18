# GO-026 — CANONICAL TASK PAYLOAD + EXPLICIT GRAPH BINDING

## Status
**DRAFT / CONTRACT**

GO-026 closes the GO-024 placeholder `{list-id}` and the empty task body without inventing production data.

### Canonical payload

`TaskCreatePayload` contains:
- `list_id`
- `title`
- optional `body`

Validation requires an explicit list ID and non-empty title. The payload is serialized as canonical JSON only after validation.

### Graph binding

`create_task + todo` is bound to:

`/me/todo/lists/{list_id}/tasks`

where `{list_id}` is an explicit payload value, not a placeholder.

### Safety order

`VALIDATE → AUTHORIZATION → EXECUTION COMMIT → SAFETY RE-CHECK → IDEMPOTENCY → PAYLOAD VALIDATION → GRAPH TRANSPORT → RECEIPT → TRACE`

GO-026 still performs no live Microsoft Graph operation.

### Constitutional invariants

- ACCESS ≠ AUTHORIZATION
- AUTHORIZATION ≠ EXECUTION
- No invented payload fields.
- No implicit resource/list selection.
- No external write without the existing execution and authorization gates.
