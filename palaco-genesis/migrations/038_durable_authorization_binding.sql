-- ∆ GO-038 — Durable authorization binding
--
-- Authorization is an external constitutional fact. This table stores only
-- the durable reference and its binding to the execution identity.
-- It does not create or grant authorization.

CREATE TABLE IF NOT EXISTS palaco_execution_authorization_binding (
    execution_id TEXT PRIMARY KEY,
    authorization_reference TEXT NOT NULL,
    authorization_state TEXT NOT NULL,
    provenance_reference TEXT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT palaco_execution_authorization_state_chk
        CHECK (authorization_state IN ('GRANTED','REVOKED','EXPIRED'))
);

CREATE INDEX IF NOT EXISTS ix_palaco_execution_auth_reference
    ON palaco_execution_authorization_binding (authorization_reference);

-- Canonical write boundary:
--
-- BEGIN
--   lock/re-read execution current state
--   require authorization_state = GRANTED
--   insert binding for execution_id
--   reject conflicting authorization_reference
-- COMMIT
--
-- Revocation/expiration updates are performed only by an authorized
-- constitutional lifecycle operation. A binding is never authority by itself.
