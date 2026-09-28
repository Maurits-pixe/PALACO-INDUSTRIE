-- ∆ GO-046 — PALACO Administrative Period Closing
--
-- Period state is durable control metadata. Historical ledger entries are not
-- deleted or rewritten by closing.

CREATE TABLE IF NOT EXISTS palaco_administrative_period (
    period_id TEXT PRIMARY KEY,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    provenance_ref TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_admin_period_range_chk
        CHECK (starts_at < ends_at),
    CONSTRAINT palaco_admin_period_state_chk
        CHECK (state IN ('OPEN','CLOSING','CLOSED','REOPENED'))
);

CREATE INDEX IF NOT EXISTS ix_palaco_admin_period_state
    ON palaco_administrative_period (state, ends_at);

-- Closing changes period state only. Ledger history remains append-only.
