-- ∆ GO-041 — Final revocation + execution proof gate
--
-- This is the last durable read immediately before an external side-effect.
-- It grants no authority and performs no external operation.

CREATE TABLE IF NOT EXISTS palaco_execution_final_gate (
    execution_id TEXT PRIMARY KEY,
    proof_sha256 TEXT NOT NULL,
    authorization_reference TEXT NOT NULL,
    provenance_reference TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Canonical pre-side-effect transaction:
--
-- BEGIN
--   LOCK authorization binding
--   RE-READ authorization state
--   REQUIRE GRANTED
--   LOCK execution current
--   REQUIRE EXECUTING
--   LOCK execution proof
--   REQUIRE exact authorization/provenance/digest/signature references
--   UPSERT final gate evidence
-- COMMIT
--
-- The external side-effect occurs only after this durable gate succeeds.
-- A subsequent authorization revocation must cause the external adapter's
-- immediate in-memory/fresh-read revocation check to fail closed.
