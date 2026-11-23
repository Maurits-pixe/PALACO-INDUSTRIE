-- PALACO INDUSTRIE v2.6 — independently deployed PostgreSQL continuity
-- DRAFT ONLY. Apply to a SEPARATE, protected authority database, never to
-- the challenge SQLite database or an unreviewed production environment.
-- Provision rows using independently reviewed administrative procedures.
CREATE SCHEMA IF NOT EXISTS palaco_continuity;

CREATE TABLE IF NOT EXISTS palaco_continuity.floor_highwater (
  namespace text PRIMARY KEY,
  epoch bigint NOT NULL CHECK(epoch >= 0),
  minimum_last_seen_ms bigint NOT NULL CHECK(minimum_last_seen_ms >= 0),
  CONSTRAINT namespace_format CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$')
);

-- NO INSERT/UPSERT in the runtime API. Bootstrap must be explicitly provisioned
-- by authorized administrators against the independently protected store.
-- This conditional single-statement UPDATE takes a PostgreSQL row lock,
-- preventing concurrent requests from silently regressing either dimension.
-- Application MUST demand exactly one returned row.
-- $1 namespace TEXT, $2 epoch BIGINT, $3 minimum floor BIGINT
-- UPDATE palaco_continuity.floor_highwater
-- SET epoch = $2, minimum_last_seen_ms = $3
-- WHERE namespace = $1 AND epoch <= $2 AND minimum_last_seen_ms <= $3
-- RETURNING epoch, minimum_last_seen_ms;

-- Deployment must separately REVOKE broad schema/table grants and grant the
-- runtime role only UPDATE(epoch, minimum_last_seen_ms), SELECT of necessary
-- predicate columns, constrained to provisioned rows. SQL permissions alone
-- do not guarantee independent state protection, backup anti-rollback or
-- trusted authentication. Separate service credentials and operational
-- controls are required.
