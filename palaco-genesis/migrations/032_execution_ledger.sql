-- ∆ GO-032 — Durable execution ledger
-- PostgreSQL migration contract.
-- The ledger is append-only. Current state is a projection used by workers
-- for fail-closed execution checks. External side effects never occur here.

CREATE TABLE IF NOT EXISTS palaco_execution_ledger (
    sequence_id BIGSERIAL PRIMARY KEY,
    execution_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    authorization_reference TEXT,
    state TEXT NOT NULL CHECK (state IN ('PENDING','EXECUTING','COMPLETED','FAILED','REVOKED','EXPIRED','CANCELLED')),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_palaco_execution_ledger_idempotency ON palaco_execution_ledger (idempotency_key);
CREATE INDEX IF NOT EXISTS ix_palaco_execution_ledger_execution ON palaco_execution_ledger (execution_id, sequence_id);

CREATE TABLE IF NOT EXISTS palaco_execution_current (
    execution_id TEXT PRIMARY KEY,
    sequence_id BIGINT NOT NULL REFERENCES palaco_execution_ledger(sequence_id),
    state TEXT NOT NULL CHECK (state IN ('PENDING','EXECUTING','COMPLETED','FAILED','REVOKED','EXPIRED','CANCELLED')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS palaco_execution_outbox (
    outbox_id BIGSERIAL PRIMARY KEY,
    sequence_id BIGINT NOT NULL REFERENCES palaco_execution_ledger(sequence_id),
    execution_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('STATE_CHANGED','REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dispatched_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_palaco_execution_outbox_pending ON palaco_execution_outbox (created_at, outbox_id) WHERE dispatched_at IS NULL;
