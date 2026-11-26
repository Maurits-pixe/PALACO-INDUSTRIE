# PALACO INDUSTRIE — Isolated Incident Write Gateway v4.5 (DRAFT / HOLD)

## Implemented boundary

`distribution/incident-write-gateway.js` provides a **process-local, branded, immutable** `createIncidentWriteGateway` interface which exposes only `submit(incident,endorsements,signal)` and the scoped namespace. Its raw PostgreSQL query callback, authenticated reviewer trust-policy provider and dual witness readers remain in the private closure. The gateway obtains reviewer keys and trusted time from the operator-provided policy provider, never from a caller-supplied request field.

Before storing any forensic incident, it requires an exact next sequence and predecessor digest from the append-only archive, two valid distinct Ed25519 reviewer signatures, an unexpired signed incident assertion of `DENY / GO-13 HOLD / QUARANTINE_NO_SYNC`, and a fresh read of **both** independent witness heads matching the signed observation. The archive adapter then repeats signature and chain checks and performs a parameterized INSERT protected by the database's unique sequence key and SQL predecessor triggers. No arbitrary UPDATE, DELETE, repair, synchronization, installation, publication or release capability is exposed by this gateway.

## CI and permission integration

`tests/distribution-incident-write-gateway.test.js` exercises full valid submission, brand forgery, SQL handle non-exposure, tampering, unreachable/mismatching live witnesses, absent trusted reviewer policy, duplicate/replayed cases, aborted requests, unavailable storage and competing writes.

`tests/postgres-incident-archive-privileges.test.js` has been updated to perform the permitted database append via the gateway while separately checking the read-only PostgreSQL role cannot insert, the restricted writer role cannot update/delete/truncate/alter triggers, and namespace RLS restricts both roles. The roles and credentials exist **only inside the disposable CI database**. Existing PostgreSQL crash and restore tests remain unchanged.

## Important limitations

- This is a **module-level trusted gateway and database role test**, NOT a deployed separate service or an RPC endpoint. No production credentials, TLS transport, process isolation, identity federation, KMS, client admission or authenticated IPC is provisioned. Hosting the gateway inside an untrusted general-purpose web process would defeat the intended separation.
- A process or operator with the writer's PostgreSQL credentials can still bypass JavaScript by issuing raw SQL INSERTs. PostgreSQL does not independently check Ed25519 signatures. True isolation requires a separately administered service with private credentials, a narrow authenticated ingestion protocol, strict network ACLs and independent key/role custody.
- Reading live witnesses and the archive head is not a distributed atomic snapshot; their state may change between verification and insert. The result therefore **never grants synchronization or repair authority**.
- No independently anchored high-watermark protects against privileged restore of the incident archive itself; that remains a required next phase.
- The existing v3.4 HTTP distribution startup interlock remains `ingress: null`. The new gateway is not exposed to HTTP routes and does not change release gating.

**Governance:** `authorization=DENY`, `go13=HOLD`, Draft PR #36. No merge, installation, production migration, publication or deployment.