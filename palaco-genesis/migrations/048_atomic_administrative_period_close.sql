-- ∆ GO-048 — Atomic Administrative Period Close
--
-- Binds reconciliation observations to an administrative reporting period.
-- The close transaction re-reads these observations while holding the period
-- row lock, so stale caller-side evidence cannot close a period.

ALTER TABLE palaco_administrative_reconciliation
    ADD COLUMN IF NOT EXISTS period_id TEXT;

CREATE INDEX IF NOT EXISTS ix_palaco_admin_reconciliation_period_outcome
    ON palaco_administrative_reconciliation (period_id, outcome, observed_at DESC);

-- Legacy observations with NULL period_id remain historical evidence but are
-- not silently assigned to a reporting period. A period close only evaluates
-- observations explicitly bound to that period.
