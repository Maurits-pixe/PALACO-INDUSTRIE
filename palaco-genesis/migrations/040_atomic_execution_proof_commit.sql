-- ∆ GO-040 — Atomic execution proof commit boundary
--
-- Durable proof creation must be atomic with the authorization binding check
-- and initial execution transition. This migration adds an immutable proof
-- identity and prevents conflicting proof material for one execution.

CREATE TABLE IF NOT EXISTS palaco_execution_proof_commit (
    execution_id TEXT PRIMARY KEY,
    authorization_reference TEXT NOT NULL,
    provenance_reference TEXT NOT NULL,
    signed_request_sha256 TEXT NOT NULL,
    signature_reference TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_palaco_execution_proof_commit_material
    ON palaco_execution_proof_commit (
        execution_id,
        authorization_reference,
        provenance_reference,
        signed_request_sha256,
        signature_reference
    );

-- Canonical transaction:
--
-- BEGIN
--   LOCK authorization binding
--   RE-READ authorization state
--   REQUIRE GRANTED
--   LOCK current execution
--   REQUIRE PENDING
--   VERIFY proof references
--   INSERT proof commit
--   APPEND EXECUTING transition
--   PROJECT EXECUTING
--   EMIT STATE_CHANGED outbox
-- COMMIT
--
-- No external network operation occurs in this transaction.
