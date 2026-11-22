# PALACO INDUSTRIE — Challenge Registry Integrity Audit v1.4 (DRAFT / HOLD)

This adds a read-only SQLite registry assessment at `distribution/challenge-registry-audit.js`. It is an independent diagnostic module; v1.3 issuance and consumption logic remains unchanged.

Call `auditDurableChallengeRegistry(db, { minimumLastSeenMs, maxRows })` using an already-open `node:sqlite` `DatabaseSync`. The function checks SQLite `PRAGMA quick_check`, the persisted clock singleton, an externally supplied lower clock bound, a configurable maximum number of stored records, and each stored record's hash, namespace, expiry and status. All errors result in `BLOCKED`, with no database writes or challenge consumption.

**Security boundary:** The minimum clock bound MUST come from a separately authenticated and rollback-resistant authority. This function does not verify that provenance. A fully restored database and an equally rolled-back bound could still pass. `quick_check` detects certain structural corruption, not semantic authenticity or malicious coordinated database replacement. The audit is not a cryptographic signature, trusted time source, durable monotonic register, consensus protocol or authorization mechanism.

This audit should be run as an independent preflight; it is not currently wired into every v1.3 issue/consume operation. Database concurrency and snapshot consistency under concurrent writers require operational coordination.

The result always includes `authorization: DENY`, `go13: HOLD`, `mayAdvance: false`, `mayRestore: false`, `mayRotate: false`, `mayPublish: false` and `mayInstall: false`. No software installation, deployment or release operation is implemented.

Local command: `node --test tests/distribution-challenge-registry-audit.test.js`. Eight tests passed on Node v22.16.0. GitHub CI and independent review remain necessary.
