# PALACO INDUSTRIE — Durable Challenge Registry v1.3 (DRAFT / HOLD)

The CommonJS module distribution/durable-challenge-registry.js supplies a persistent one-time challenge registry using Node's built-in SQLite DatabaseSync.

It exports initializeDurableChallengeSchema(db) and createDurableChallengeRegistry(db, {ttlMs,maxPending,clock}). Use issue(namespace) to create a random 256-bit challenge, or consume(namespace,challenge,state,endorsement,pinnedRoots,minimumSequence) to atomically mark it consumed BEFORE invoking the v1.1 Ed25519 verification. The registry stores a domain-separated SHA-256 hash, never the raw challenge. BEGIN IMMEDIATE serializes writers using the same SQLite database, and consumed hashes remain for replay detection after process restarts.

The default TTL is 60 seconds and maximum active pending count is 128. A persisted last-seen wall clock rejects backward time changes as long as the database itself is not restored. Invalid, expired, unknown or misrouted challenges fail closed. Process restart preserves both pending and consumed status.

**Limitations:** Reverting the database file can resurrect old challenges. This is not hardware-backed monotonic storage, independently authenticated time, consensus, or a network authority. A production design requires protected disk permissions, reliable backups, independent anti-rollback anchors, multi-process operational controls and independent authority trust. Expired and consumed records remain retained; pruning needs a reviewed retention policy.

All resulting assessments preserve authorization DENY, GO-13 HOLD, and false publication/installation permissions. There is no merge, deployment, or external side effect.

Run: node --test tests/distribution-durable-challenge-registry.test.js. Tests are added for restart durability, replay, expiry, signature failure, namespace isolation, capacity and clock rollback.
