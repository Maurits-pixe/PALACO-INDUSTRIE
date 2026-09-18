-- ∆ GO-047 — Administrative Closing Evidence Gate
--
-- Durable evidence for controlled period closing. The gate does not itself
-- perform authorization or mutate ledger history.

CREATE TABLE IF NOT EXISTS palaco_administrative_closing_gate (
    period_id TEXT PRIMARY KEY,
    reconciliation_provenance TEXT NOT NULL,
    report_provenance TEXT NOT NULL,
    unresolved_mismatches BIGINT NOT NULL DEFAULT 0,
    unresolved_unknowns BIGINT NOT NULL DEFAULT 0,
    decision_ref TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_admin_closing_counts_chk
        CHECK (unresolved_mismatches >= 0 AND unresolved_unknowns >= 0)
);

-- A later implementation can atomically lock the OPEN/CLOSING period,
-- re-read the evidence, require zero unresolved observations, persist the
-- gate, and then transition the period to CLOSED.
