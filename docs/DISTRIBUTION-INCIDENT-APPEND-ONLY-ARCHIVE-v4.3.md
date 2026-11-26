# PALACO INDUSTRIE — Append-only Forensic Incident Archive v4.3 (DRAFT / HOLD)

## Scope and verification

`distribution/sql/incident-append-only-v4.3.sql` specifies a separately provisioned `palaco_incident_archive.entries` table indexed by `(namespace,sequence)` with unique incident ID and digest. Every row stores a cryptographically linked predecessor digest, canonical incident hash, the complete incident JSON dossier, and both signed reviewer endorsement objects. SQL triggers reject UPDATE, DELETE, TRUNCATE, skipped incident sequences, and inconsistent predecessor digests. Postgres unique constraints reject two competing inserts for the same namespace/sequence.

`distribution/incident-append-only-archive.js` exposes only `latest` and `appendReviewed`, not a generic archive mutation method. The adapter reads the latest head and validates strictly sequential `sequence` and `priorIncidentDigest`, then re-verifies the two Ed25519 signatures using externally supplied trusted reviewer roots and time. It inserts a reviewed incident with a single parameterized PostgreSQL INSERT. A missing head/query, invalid signature, forged successor, database error, concurrent conflicting insert or ambiguous return is **DENY/HOLD**. Every successful append is purely forensic: no repair, synchronization, authority, installation or publication.

## Tests

`tests/distribution-incident-archive.test.js` covers two consecutively signed incident entries, rejection of old/replayed/skipped/wrong-predecessor incidents, tampered signatures, missing quorum, unavailable storage, aborted writes and ambiguous database acknowledgements.

`tests/postgres-incident-archive.test.js` runs in the disposable GitHub Actions PostgreSQL 17 service. It stores two signed incidents, reads back their JSON dossiers and signatures, rejects a historical replay, verifies SQL UPDATE/DELETE/TRUNCATE protections and rejects an out-of-sequence or mismatching predecessor INSERT.

## Operational trust assumptions and limitations

- The SQL schema is a deployable **specification** committed to Draft PR #36, not a production migration. A separately owned and secured database, independently provisioned reviewer trust roots, restricted runtime SQL role, and durable backup/monitoring are required for real independence.
- PostgreSQL owners and superusers can disable triggers, alter constraints or restore backups; the append-only guarantee applies to the configured role/trigger boundary, not to hostile superusers or media replacement. An external monotonic ledger head or cryptographic transparency log is needed to detect rollback of the archive's own storage.
- The archive stores signatures and payload data, but PostgreSQL triggers do **not** cryptographically verify signatures by themselves. A database role with direct INSERT access can bypass application review even though sequence and hash linkage remain checked by triggers. Only the reviewed adapter should have access; a least-privilege write mediator, cryptographically checked append function or trusted proxy is still required for a stronger trust boundary.
- This archive records **signed incident claims**. A separate live witness check from v4.2 is necessary to establish current observational matching; archives must preserve historical facts even when the witnesses later change.
- The `latest` then `INSERT` protocol is protected by unique sequence constraints against concurrent append races, but it is not a distributed consensus algorithm and does not provide globally atomic snapshots of independent witness stores.
- No HTTP distribution endpoint, operational authority transition, or incident repair API is added; the v3.4 startup interlock remains `ingress:null`.

**Governance:** `authorization=DENY`, `GO-13=HOLD`. No PR merge, deployment, publication, production key provisioning or installation.