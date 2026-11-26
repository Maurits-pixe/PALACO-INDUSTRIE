# PALACO INDUSTRIE — Signed Incident Witness Handoff v4.7 (DRAFT / HOLD)

## Scope

`distribution/incident-witness-handoff.js` defines domain-separated canonical Ed25519-signed handoff evidence for one adjacent incident witness revision, including namespace, sender and recipient identities, unique nonce, old/new sequence and SHA-256 digest, expiry, and mandatory `DENY/HOLD` plus `EVIDENCE_ONLY_NO_RELEASE`. The recipient signs a **separate receipt** that binds the recipient ID, nonce, handoff digest and observed acceptance time; the acknowledgement is explicitly `EVIDENCE_RECEIVED_NO_AUTHORITY`.

The verifier enforces independently pinned issuer and recipient public keys, distinct identities and keys, correct signature payloads, matching namespace and recipient, exact externally trusted predecessor revision and digest, and bounded non-expired timestamps. Cryptographic evidence is never treated as permission to repair, synchronize, install, deploy or release.

`distribution/incident-witness-handoff-receiver.js` uses a trusted policy provider and a separate PostgreSQL witness connection; it does not take reviewer roots, trust anchors or policy clocks from untrusted handoff data. After verification it performs one atomic parameterized PostgreSQL statement with a compare-and-swap witness-head update and a same-statement insert into the immutable receipt/nonce registry. A concurrent conflict, duplicate nonce, repeated handoff, missing witness head, signature mismatch or ambiguous SQL acknowledgement fails closed.

`distribution/sql/incident-witness-receipts-v4.7.sql` creates `palaco_incident_witness.receipts` with unique namespace/nonce, namespace/handoff digest and namespace/sequence constraints and SQL triggers against UPDATE, DELETE and TRUNCATE. This is a provisionable contract only, NOT a production migration.

## Verification

`tests/distribution-incident-witness-handoff.test.js` covers valid two-signature receipt, tampering, identity/recipient rebinding, revoked signing keys, missing trusted anchor, expiry, nonce replay and private SQL handle boundaries. `tests/postgres-incident-witness-handoff.test.js` uses a disposable restricted PostgreSQL 17 principal (SELECT+column-limited UPDATE on witness heads, SELECT/INSERT on receipt registry, namespace RLS), checks a valid signed handoff, verifies the stored nonce and new witness head, rejects replay and attempts to delete/truncate receipts, disable triggers or roll back the witness head.

## Operational limits

- The proof of receipt means **cryptographic acknowledgement by a key**, not independent custody, human identity, valid recovery judgment or a release authorization.
- The CI database roles and test passwords are disposable. Both archive and witness still share a CI PostgreSQL failure and administration domain; truly independent witness storage, credential isolation, network mTLS, KMS, incident alerting and audited recovery are not deployed.
- This is a trusted-module receiver, not a standalone service. A holder of direct witness SQL UPDATE/INSERT credentials may bypass the JavaScript signature verification and must therefore never be a general-purpose application runtime or public HTTP principal.
- Receipt insertion and witness-head update are atomic in one PostgreSQL statement. External incident-archive writes remain **outside** that database transaction; there is no distributed commit, global consensus or cross-service atomicity. Divergence must stay under HOLD and is not automatically repaired.
- A database owner or privileged administrator can replace schema/backup and bypass trigger protections. Durable independent ledger roots and secure operator provisioning remain additional necessary safeguards.

**Governance:** `authorization=DENY`, `go13=HOLD`. No merge, production role provisioning, publishing, deployment, installation, synchronization or release. Draft PR #36 only.