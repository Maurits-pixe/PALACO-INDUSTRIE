-- ∆ GO-035 — Crash-safe transactional outbox leasing
--
-- Claim and acknowledgement are deliberately separate.
-- A crash after claim leaves the signal eligible again after lease expiry.

ALTER TABLE palaco_execution_outbox
    ADD COLUMN IF NOT EXISTS leased_by TEXT;

ALTER TABLE palaco_execution_outbox
    ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS ix_palaco_execution_outbox_lease
    ON palaco_execution_outbox (lease_until, outbox_id)
    WHERE dispatched_at IS NULL;
