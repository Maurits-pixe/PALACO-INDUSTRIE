-- ∆ GO-042 — External side-effect receipt + reconciliation
--
-- External acceptance, rejection, and unknown outcomes are durable evidence.
-- UNKNOWN is deliberately not projected as successful execution.

CREATE TABLE IF NOT EXISTS palaco_external_receipt (
    receipt_id BIGSERIAL PRIMARY KEY,
    execution_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    external_system TEXT NOT NULL,
    external_reference TEXT,
    outcome TEXT NOT NULL,
    signed_request_sha256 TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_external_receipt_outcome_chk
        CHECK (outcome IN ('ACCEPTED','REJECTED','UNKNOWN'))
);

CREATE INDEX IF NOT EXISTS ix_palaco_external_receipt_execution
    ON palaco_external_receipt (execution_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS palaco_external_reconciliation (
    execution_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    last_receipt_id BIGINT NOT NULL REFERENCES palaco_external_receipt(receipt_id),
    reconciled_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_external_reconciliation_state_chk
        CHECK (state IN ('CONFIRMED','REJECTED','PENDING'))
);

-- UNKNOWN must remain recoverable and must not be silently converted into
-- COMPLETED. A later reconciliation may establish the external state.
