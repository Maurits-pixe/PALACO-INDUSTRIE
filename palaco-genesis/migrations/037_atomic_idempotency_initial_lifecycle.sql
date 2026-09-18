-- ∆ GO-037 — Atomic idempotency claim + initial lifecycle
--
-- Contract:
-- BEGIN
--   claim idempotency
--   create PENDING lifecycle
--   project current state
--   emit outbox signal
-- COMMIT
--
-- The application must execute this statement set in one PostgreSQL transaction.
-- A duplicate idempotency key must not create a second lifecycle.

CREATE TABLE IF NOT EXISTS palaco_execution_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_palaco_execution_idempotency_execution
    ON palaco_execution_idempotency (execution_id);

-- Canonical transaction template:
--
-- INSERT INTO palaco_execution_idempotency
--     (idempotency_key, execution_id)
-- VALUES ($1, $2)
-- ON CONFLICT (idempotency_key) DO NOTHING;
--
-- If INSERT affected one row:
--   INSERT PENDING into palaco_execution_ledger;
--   INSERT/UPSERT PENDING into palaco_execution_current;
--   INSERT INITIAL/PENDING signal into palaco_execution_outbox;
--   COMMIT.
--
-- If INSERT affected zero rows:
--   ROLLBACK/return the existing execution_id;
--   do not create lifecycle or outbox duplicates.
