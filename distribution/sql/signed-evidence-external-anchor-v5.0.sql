-- Admin-managed independent database. No live application mutation path.
CREATE SCHEMA IF NOT EXISTS palaco_signed_evidence_anchor;
CREATE TABLE IF NOT EXISTS palaco_signed_evidence_anchor.latest (
 namespace text PRIMARY KEY CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence>=2),
 chain_digest text NOT NULL CHECK(chain_digest ~ '^[a-f0-9]{64}$')
);
CREATE OR REPLACE FUNCTION palaco_signed_evidence_anchor.guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW.namespace IS DISTINCT FROM OLD.namespace OR
    NEW.sequence<>OLD.sequence+1 OR
    NEW.chain_digest IS NOT DISTINCT FROM OLD.chain_digest THEN
   RAISE EXCEPTION 'signed evidence anchor rollback' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'signed evidence anchor delete or truncate'
 USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS guard_evidence_anchor_update
 ON palaco_signed_evidence_anchor.latest;
CREATE TRIGGER guard_evidence_anchor_update
BEFORE UPDATE ON palaco_signed_evidence_anchor.latest
FOR EACH ROW EXECUTE FUNCTION palaco_signed_evidence_anchor.guard();
DROP TRIGGER IF EXISTS guard_evidence_anchor_delete
 ON palaco_signed_evidence_anchor.latest;
CREATE TRIGGER guard_evidence_anchor_delete
BEFORE DELETE ON palaco_signed_evidence_anchor.latest
FOR EACH ROW EXECUTE FUNCTION palaco_signed_evidence_anchor.guard();
DROP TRIGGER IF EXISTS guard_evidence_anchor_truncate
 ON palaco_signed_evidence_anchor.latest;
CREATE TRIGGER guard_evidence_anchor_truncate
BEFORE TRUNCATE ON palaco_signed_evidence_anchor.latest
FOR EACH STATEMENT EXECUTE FUNCTION palaco_signed_evidence_anchor.guard();
