-- PALACO INDUSTRIE v3.9: separate authority-reference high-watermark.
-- Provision only by a trusted administrator in a separately controlled DB.
-- Runtime may SELECT and execute constrained compare-and-advance, never INSERT,
-- DELETE, TRUNCATE, ALTER TABLE or reset revisions. No automatic bootstrap.
CREATE SCHEMA IF NOT EXISTS palaco_authority_anchor;
CREATE TABLE IF NOT EXISTS palaco_authority_anchor.latest (
  namespace text PRIMARY KEY,
  revision bigint NOT NULL CHECK (revision >= 1),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT namespace_format CHECK (namespace ~ '^[a-z][a-z0-9._-]{2,79}$')
);

CREATE OR REPLACE FUNCTION palaco_authority_anchor.reject_latest_regression()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF NEW.namespace IS DISTINCT FROM OLD.namespace
     OR NEW.revision <= OLD.revision
     OR NEW.revision <> OLD.revision + 1
     OR NEW.state_digest IS NOT DISTINCT FROM OLD.state_digest THEN
    RAISE EXCEPTION 'authority anchor rollback or invalid progression'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_authority_revision
ON palaco_authority_anchor.latest;
CREATE TRIGGER guard_authority_revision
BEFORE UPDATE ON palaco_authority_anchor.latest
FOR EACH ROW EXECUTE FUNCTION palaco_authority_anchor.reject_latest_regression();
