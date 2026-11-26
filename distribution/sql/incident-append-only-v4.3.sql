-- PALACO INDUSTRIE v4.3 — isolated append-only incident evidence ledger.
-- ADMIN-ONLY SCHEMA. Runtime must never own the table or hold UPDATE/DELETE.
CREATE SCHEMA IF NOT EXISTS palaco_incident_archive;
CREATE TABLE IF NOT EXISTS palaco_incident_archive.entries (
  namespace text NOT NULL CHECK (namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
  sequence bigint NOT NULL CHECK (sequence > 0),
  incident_id text NOT NULL CHECK (incident_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
  prior_digest text NOT NULL CHECK (prior_digest ~ '^[0-9a-f]{64}$'),
  incident_digest text NOT NULL CHECK (incident_digest ~ '^[0-9a-f]{64}$'),
  observed_at_ms bigint NOT NULL CHECK (observed_at_ms >= 0),
  dossier jsonb NOT NULL CHECK (jsonb_typeof(dossier) = 'object'),
  endorsements jsonb NOT NULL CHECK (jsonb_typeof(endorsements) = 'array'),
  PRIMARY KEY(namespace,sequence),
  UNIQUE(namespace,incident_id),
  UNIQUE(namespace,incident_digest)
);
CREATE OR REPLACE FUNCTION palaco_incident_archive.reject_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp
AS $$
BEGIN
  RAISE EXCEPTION 'incident evidence is append-only'
    USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS reject_incident_mutation ON palaco_incident_archive.entries;
CREATE TRIGGER reject_incident_mutation
BEFORE UPDATE OR DELETE ON palaco_incident_archive.entries
FOR EACH ROW EXECUTE FUNCTION palaco_incident_archive.reject_mutation();

-- Appends require contiguous predecessor sequence AND exact predecessor
-- digest. A standalone DO/VALUES insert cannot insert a later chain entry.
-- INSERT is protected by primary-key uniqueness against concurrent same-step
-- writers; on conflict the caller must fail closed and re-check the head.
CREATE OR REPLACE FUNCTION palaco_incident_archive.validate_append()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp
AS $$
DECLARE prior record;
BEGIN
  IF NEW.sequence = 1 THEN
    IF NEW.prior_digest <> repeat('0',64) THEN
      RAISE EXCEPTION 'invalid genesis incident'
        USING ERRCODE='23514';
    END IF;
  ELSE
    SELECT sequence,incident_digest INTO prior
      FROM palaco_incident_archive.entries
      WHERE namespace=NEW.namespace AND sequence=NEW.sequence-1;
    IF NOT FOUND OR prior.incident_digest IS DISTINCT FROM NEW.prior_digest THEN
      RAISE EXCEPTION 'incident chain predecessor mismatch'
        USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS validate_incident_append ON palaco_incident_archive.entries;
CREATE TRIGGER validate_incident_append
BEFORE INSERT ON palaco_incident_archive.entries
FOR EACH ROW EXECUTE FUNCTION palaco_incident_archive.validate_append();

-- TRUNCATE does not emit row DELETE triggers: deny it independently.
DROP TRIGGER IF EXISTS reject_incident_truncate ON palaco_incident_archive.entries;
CREATE TRIGGER reject_incident_truncate
BEFORE TRUNCATE ON palaco_incident_archive.entries
FOR EACH STATEMENT EXECUTE FUNCTION palaco_incident_archive.reject_mutation();
