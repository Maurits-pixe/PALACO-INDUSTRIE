-- ∆ GO-039 — Durable execution proof
--
-- This record binds durable execution identity to the exact signed request
-- digest and authorization/provenance references. It does not grant authority.

CREATE TABLE IF NOT EXISTS palaco_execution_proof (
    execution_id TEXT PRIMARY KEY,
    authorization_reference TEXT NOT NULL,
    provenance_reference TEXT NOT NULL,
    signed_request_sha256 TEXT NOT NULL,
    signature_reference TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_palaco_execution_proof_request
    ON palaco_execution_proof (execution_id, signed_request_sha256);

-- Atomic binding boundary:
-- BEGIN
--   LOCK authorization binding
--   REQUIRE authorization state = GRANTED
--   LOCK/re-read execution
--   INSERT execution proof
--   COMMIT
--
-- External side effects remain outside this transaction.
