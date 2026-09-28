-- ∆ GO-044 — PALACO Administrative Ledger
--
-- Append-only administrative facts. This is a record/evidence layer, not an
-- authorization or payment mechanism.

CREATE TABLE IF NOT EXISTS palaco_administrative_ledger (
    sequence BIGSERIAL PRIMARY KEY,
    record_id TEXT NOT NULL,
    fact_type TEXT NOT NULL,
    amount_minor BIGINT,
    currency CHAR(3),
    provenance_ref TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_admin_ledger_currency_chk
        CHECK (
            (amount_minor IS NULL AND currency IS NULL)
            OR
            (amount_minor IS NOT NULL AND currency IS NOT NULL AND btrim(currency) <> '')
        )
);

CREATE INDEX IF NOT EXISTS ix_palaco_admin_ledger_record
    ON palaco_administrative_ledger (record_id, sequence);

CREATE INDEX IF NOT EXISTS ix_palaco_admin_ledger_provenance
    ON palaco_administrative_ledger (provenance_ref, sequence);

-- No UPDATE/DELETE contract is introduced here: the ledger is append-only.
