-- ∆ GO-045 — PALACO Administrative Reconciliation
--
-- Reconciliation records observations; it does not authorize or execute actions.

CREATE TABLE IF NOT EXISTS palaco_administrative_reconciliation (
    reconciliation_id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    outcome TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_admin_reconciliation_outcome_chk
        CHECK (outcome IN ('MATCHED','MISMATCHED','MISSING','DUPLICATE','UNKNOWN'))
);

CREATE INDEX IF NOT EXISTS ix_palaco_admin_reconciliation_record
    ON palaco_administrative_reconciliation (record_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS ix_palaco_admin_reconciliation_source
    ON palaco_administrative_reconciliation (source_ref, observed_at DESC);

-- Historical observations remain append-only. A new observation receives a
-- new reconciliation_id rather than mutating prior evidence.
