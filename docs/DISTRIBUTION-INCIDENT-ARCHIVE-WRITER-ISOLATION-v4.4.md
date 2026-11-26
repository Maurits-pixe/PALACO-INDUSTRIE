# PALACO INDUSTRIE — Restricted Incident Archive Writer v4.4 (DRAFT / HOLD)

## Implemented and tested

`tests/postgres-incident-archive-privileges.test.js` runs against a **throwaway PostgreSQL 17 service** in GitHub Actions. Its admin creates two test-only login roles and binds both to the `palaco_incident_archive.entries` schema with REVOKE FROM PUBLIC, grants, and row-level security:

- `palaco_archive_reader_v44`: schema USAGE, SELECT only; can read the scoped incident history and cannot INSERT/UPDATE/DELETE/TRUNCATE or alter triggers.
- `palaco_archive_writer_v44`: schema USAGE, SELECT and INSERT only; row-level security restricts visible and insertable namespaces to `palaco.v44ci`, and no UPDATE/DELETE/TRUNCATE/ALTER capabilities are granted.
- The writer uses the existing `createIncidentArchive().appendReviewed()` path, which validates two Ed25519 signatures, a trusted reviewer policy, and the expected incident chain before issuing a parameterized SQL INSERT.
- Test reads the persisted digest through the reader role, verifies the writer role can append only an in-scope reviewed incident and confirms both principals cannot mutate existing evidence.

### Security scope

This demonstrates **DB permissions and separated application-level access**; it does not deploy a production service or roles, does not secure a production account, and does not modify `server.js`. The runtime HTTP distribution interlock remains unconditionally closed.

**Important gap:** a PostgreSQL role possessing raw INSERT privileges could bypass application-level Ed25519 verification by constructing an SQL insert with a matching predecessor and fabricated dossier/endorsement JSON. Database triggers currently validate sequence/digest linkage, not the signature authenticity of inserted evidence. Production hardening needs a separately authenticated trusted append gateway or a write-only database function with cryptographic verification, plus the writer credentials hidden from general-purpose services. Never expose raw INSERT credentials to the web runtime.

### Additional limitations

- The table owner or PostgreSQL superuser may change grants, disable RLS, triggers or restore backups. RLS does not defend against a malicious table owner.
- The demonstration uses CI-only static passwords and roles; no production credentials or external separate infrastructure has been provisioned.
- The archive still lacks an independently anchored high-watermark to detect rollback of the incident database itself.
- Test-only row-level security policies are not a production migration. The DBA must independently provision principals, per-namespace RLS and network/TLS isolation before any operational consideration.

All incident verification and append outcomes remain non-authorizing: `authorization=DENY`, `go13=HOLD`, no synchronization, restoration, installation, publication or release. Draft PR #36 only, no merge or deployment.