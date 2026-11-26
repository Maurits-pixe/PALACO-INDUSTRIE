# PALACO INDUSTRIE — External Incident Archive Witness v4.6 (DRAFT / HOLD)

## Implemented

`distribution/incident-external-witness.js` provides a read-only adapter to an out-of-band, independently hosted and administered incident-archive high-watermark. `verifyIncidentArchiveWitness()` compares the archive's current `(sequence,digest)` with the separate witness's exact head; missing, malformed, unreachable, older, advanced or mismatched heads all fail closed. Even a matching witness is solely non-authorizing evidence: `authorization=DENY`, `go13=HOLD`, `mayRestore=false`, `maySynchronize=false`, and no operational ingress or release.

`distribution/sql/incident-external-witness-v4.6.sql` defines the separately provisionable PostgreSQL witness table and trigger guards. The witness sequence must advance by exactly one with a different SHA-256 digest. UPDATE rollback, DELETE and TRUNCATE are rejected by trigger. The adapter itself has **no write method** and never provisions witness credentials, upgrades schemas or synchronizes archives.

## Verification

`tests/distribution-incident-external-witness.test.js` covers exact matches, rollback, same-sequence digest mismatch, unavailable/malformed sources, abort and missing writer interface.

`tests/postgres-incident-external-witness.test.js` runs a controlled, privileged backup-restore simulation in CI. It uses a separate PostgreSQL database for the witness and a primary incident archive database; starts both at incident 2, then recreates the primary schema with only incident 1. The independent witness stays at incident 2 and the verifier returns `INCIDENT_WITNESS_HEAD_MISMATCH` with DENY/HOLD. It also tests a direct backward database update refused by the witness trigger.

## Security limitations

- Both test databases use the same PostgreSQL server and administrator. This proves detection of a **one-sided** privileged restore, not true independent infrastructure, separate operator custody, immutable backups or protection against coordinated compromise.
- Owners and database superusers can drop triggers, alter schemas or deliberately restore the witness database too. A production witness requires separate trusted operators, storage, backup/restore domain, private credentials, TLS and monitoring.
- The witness is **read-only in v4.6**, with its head independently provisioned and advanced by authorized operators in the CI fixture. There is no automatic two-phase commit or cross-store synchronization; any divergence deliberately remains under HOLD.
- This verifier does not prevent a malicious writer with direct SQL credentials from bypassing application signature checks. The v4.5 gateway remains process-local and requires isolation in a separate authenticated service for production use.
- A successful head comparison is a point-in-time observation, not an atomic cross-system snapshot, and can never authorize writes, reconciliation or deployment.

The existing HTTP distribution routes remain shut by the unconditional startup interlock. Draft PR #36, `GO-13 HOLD`; no merge, deployment, release or production changes.