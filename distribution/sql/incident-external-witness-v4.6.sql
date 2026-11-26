-- PALACO INDUSTRIE v4.6: provision separately from the incident archive
-- by an independent trusted administrator. This is NOT a runtime migration.
CREATE SCHEMA IF NOT EXISTS palaco_incident_witness;
CREATE TABLE IF NOT EXISTS palaco_incident_witness.heads (
 namespace text PRIMARY KEY CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence >= 1),
 incident_digest text NOT NULL CHECK(incident_digest ~ '^[a-f0-9]{64}$')
);
CREATE OR REPLACE FUNCTION palaco_incident_witness.reject_regression()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.namespace IS DISTINCT FROM OLD.namespace OR
    NEW.sequence <> OLD.sequence + 1 OR
    NEW.incident_digest IS NOT DISTINCT FROM OLD.incident_digest THEN
  RAISE EXCEPTION 'incident witness rollback or invalid progression'
   USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_incident_witness ON palaco_incident_witness.heads;
CREATE TRIGGER guard_incident_witness
BEFORE UPDATE ON palaco_incident_witness.heads FOR EACH ROW
EXECUTE FUNCTION palaco_incident_witness.reject_regression();
CREATE OR REPLACE FUNCTION palaco_incident_witness.reject_removal()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'incident witness immutable history'
  USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS guard_incident_witness_delete ON palaco_incident_witness.heads;
CREATE TRIGGER guard_incident_witness_delete
BEFORE DELETE ON palaco_incident_witness.heads FOR EACH ROW
EXECUTE FUNCTION palaco_incident_witness.reject_removal();
DROP TRIGGER IF EXISTS guard_incident_witness_truncate ON palaco_incident_witness.heads;
CREATE TRIGGER guard_incident_witness_truncate
BEFORE TRUNCATE ON palaco_incident_witness.heads FOR EACH STATEMENT
EXECUTE FUNCTION palaco_incident_witness.reject_removal();
