-- ∆ GO-043 — PALACO Administration Engine foundation
--
-- Administrative records are evidence-bearing records. This schema does not
-- create authorization and does not execute or settle financial actions.

CREATE TABLE IF NOT EXISTS palaco_administrative_fact (
    record_id TEXT PRIMARY KEY,
    identity_ref TEXT NOT NULL,
    provenance_ref TEXT NOT NULL,
    fact_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_palaco_administrative_fact_identity
    ON palaco_administrative_fact (identity_ref, recorded_at DESC);

CREATE INDEX IF NOT EXISTS ix_palaco_administrative_fact_provenance
    ON palaco_administrative_fact (provenance_ref);
