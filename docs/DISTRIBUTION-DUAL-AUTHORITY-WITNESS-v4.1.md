# PALACO INDUSTRIE — Dual Authority Witness Restore Detection v4.1 (DRAFT / HOLD)

## New capability

`distribution/dual-authority-witness.js` performs a strictly **read-only** check against two distinct, caller-supplied authority-anchor store instances. It compares the exact revision and digest of their latest recorded authority head, then compares them with the expected, canonical digest of the previous authority history. Any mismatch, missing/unreachable store, malformed expected head or abort produces `BLOCKED / DENY / GO-13 HOLD`. There is no fallback to one available witness, automatic repair, publication, installation, rotation or persistence.

`verifyRotation()` additionally verifies the four-party signed rotation record from v3.8 only after both witnesses agree on the predecessor revision/digest. Even successfully verified evidence remains non-authorizing (`mayAdvance=false`, `mayRotate=false`, `mayRestore=false`, `mayInstall=false`, `mayPublish=false`).

## Live simulated restore test

`tests/postgres-dual-authority-witness.test.js` uses two **distinct PostgreSQL databases** in the disposable GitHub Actions PostgreSQL 17 service. It seeds matching authority revision 10; verifies a four-party signed candidate revision 11; moves the secondary witness to revision 11; and simulates a privileged restoration of the primary database to revision 10 using TRUNCATE/INSERT. The dual verifier must return `DUAL_AUTHORITY_WITNESS_DIVERGENCE` and DENY/HOLD. It then tests equal revision but mismatched digest. Additional offline regressions cover missing, stale or unreachable witness, aborted requests, and a missing co-signature.

## Limits: CI is NOT real independence

- Both CI databases share **one PostgreSQL server, administrator and failure domain**. This demonstrates cross-database restore detection when the secondary database has not been rolled back; it **does not prove** independent operators, hosts, credentials, durability or protection from a coordinated restore of both stores.
- Production must place the second witness under separate operational ownership, distinct credentials, storage/backup and restore jurisdiction, TLS-pinned connectivity, continuous monitoring and a durable anti-rollback high-watermark. The current adapter cannot attest any of those properties.
- The stores are passed as references by trusted application code; using two wrapper objects backed by the same physical database defeats the independence assumption. Object identity validation is only a programming check, not infrastructure attestation.
- This verifier does **not** serialize concurrent dual-witness updates, solve distributed commit/consensus, or modify either anchor. Split-brain divergence intentionally blocks; manual, audited reconciliation is required.
- The module is not mounted into the running HTTP server. The existing startup interlock still returns `ingress:null`, so all distribution issue/consume routes remain closed.

No merge, installation, publication, production migration, privileged credential provisioning or release. Draft PR #36 remains `authorization=DENY`, `GO-13 HOLD`.