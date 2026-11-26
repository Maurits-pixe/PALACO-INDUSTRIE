# PALACO INDUSTRIE — In-Transaction Registry Audit v1.5 (DRAFT / HOLD)

v1.5 adds createAuditedDurableChallengeRegistry(db, { minimumLastSeenMs, maxRows, ttlMs, maxPending, clock }) as an opt-in guarded factory in distribution/durable-challenge-registry.js.

The guarded factory requires an independently trusted clock floor (safe nonnegative integer or callback). Inside BEGIN IMMEDIATE, it reads the stored clock, checks it against the floor BEFORE updating it, and uses that same floor reading for auditDurableChallengeRegistry inside the transaction. This prevents a restored low clock from being hidden by an updated wall clock. A missing clock row, failed audit, malformed record, or lost database fails closed with rollback.

The audit uses SQLite PRAGMA quick_check, verifies registry metadata, and enforces the caller's maximum audit row count. Both issuance and consumption are gated before mutation. Existing v1.3 createDurableChallengeRegistry remains available for compatibility and is NOT automatically secured by this wrapper.

SECURITY BOUNDARIES: A caller-supplied floor is not independently authenticated by this code. It MUST come from a separate rollback-resistant trusted authority, not from the registry being checked or the backup being restored. The guarded factory refuses a missing clock row: an independently authorized provisioning or recovery path must establish the starting state. Concurrent writers using this same SQLite database are serialized; unrelated database files or attacker-controlled file replacement are not protected. Full-table audits may be expensive at scale. A complete hardware monotonic register, multi-node consensus and cryptographic proof of clock freshness are outside scope.

Run: node --test tests/distribution-audited-challenge-registry.test.js

All assessment results preserve authorization DENY, GO-13 HOLD, mayInstall false, mayPublish false. No merge, release, credential issuance, installation or deployment is implemented.
