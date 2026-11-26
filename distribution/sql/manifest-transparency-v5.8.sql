-- PALACO INDUSTRIE v5.8: independently anchored append-only history.
-- CI only. Production requires independent operators and fault domains.
CREATE SCHEMA IF NOT EXISTS palaco_manifest_transparency;
CREATE TABLE IF NOT EXISTS palaco_manifest_transparency.entries (
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 entry_sequence bigint NOT NULL CHECK(entry_sequence>=1),
 previous_entry_digest text NOT NULL CHECK(previous_entry_digest ~ '^[a-f0-9]{64}$'),
 entry_digest text NOT NULL CHECK(entry_digest ~ '^[a-f0-9]{64}$'),
 rotation_number bigint NOT NULL CHECK(rotation_number>=1),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 previous_manifest_digest text NOT NULL CHECK(previous_manifest_digest ~ '^[a-f0-9]{64}$'),
 observer_id text NOT NULL CHECK(observer_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>=0),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9+/]{86}==$'),
 PRIMARY KEY(namespace,entry_sequence),
 UNIQUE(namespace,rotation_number,observer_id),
 UNIQUE(namespace,entry_digest),
 CHECK(entry_digest<>previous_entry_digest)
);
CREATE OR REPLACE FUNCTION palaco_manifest_transparency.guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE prior_sequence bigint;
DECLARE prior_digest text;
BEGIN
 IF TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'manifest transparency log is immutable'
   USING ERRCODE='23514';
 END IF;
 -- Serialize namespace writers even when the last row does not yet exist.
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.namespace,5800));
 SELECT entry_sequence,entry_digest INTO prior_sequence,prior_digest
 FROM palaco_manifest_transparency.entries
 WHERE namespace=NEW.namespace ORDER BY entry_sequence DESC LIMIT 1;
 IF prior_sequence IS NULL THEN
  IF NEW.entry_sequence<>1 OR NEW.previous_entry_digest<>repeat('0',64) THEN
   RAISE EXCEPTION 'manifest transparency genesis mismatch'
    USING ERRCODE='23514';
  END IF;
 ELSIF NEW.entry_sequence<>prior_sequence+1 OR
   NEW.previous_entry_digest<>prior_digest THEN
  RAISE EXCEPTION 'manifest transparency missing or divergent predecessor'
   USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_transparency_insert ON palaco_manifest_transparency.entries;
CREATE TRIGGER guard_transparency_insert BEFORE INSERT
ON palaco_manifest_transparency.entries FOR EACH ROW
EXECUTE FUNCTION palaco_manifest_transparency.guard();
DROP TRIGGER IF EXISTS guard_transparency_change ON palaco_manifest_transparency.entries;
CREATE TRIGGER guard_transparency_change BEFORE UPDATE OR DELETE
ON palaco_manifest_transparency.entries FOR EACH ROW
EXECUTE FUNCTION palaco_manifest_transparency.guard();
DROP TRIGGER IF EXISTS guard_transparency_truncate ON palaco_manifest_transparency.entries;
CREATE TRIGGER guard_transparency_truncate BEFORE TRUNCATE
ON palaco_manifest_transparency.entries FOR EACH STATEMENT
EXECUTE FUNCTION palaco_manifest_transparency.guard();

-- Entirely separate database under separate operational custody in production.
CREATE SCHEMA IF NOT EXISTS palaco_manifest_transparency_anchor;
CREATE TABLE IF NOT EXISTS palaco_manifest_transparency_anchor.latest (
 namespace text PRIMARY KEY CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 entry_sequence bigint NOT NULL CHECK(entry_sequence>=1),
 entry_digest text NOT NULL CHECK(entry_digest ~ '^[a-f0-9]{64}$'),
 observer_id text NOT NULL CHECK(observer_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>=0),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9+/]{86}==$')
);
CREATE OR REPLACE FUNCTION palaco_manifest_transparency_anchor.guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' THEN
  IF NEW.namespace IS DISTINCT FROM OLD.namespace OR
    NEW.entry_sequence<>OLD.entry_sequence+1 OR
    NEW.entry_digest IS NOT DISTINCT FROM OLD.entry_digest THEN
   RAISE EXCEPTION 'manifest transparency anchor regression'
    USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'manifest transparency anchor cannot be removed'
  USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS guard_transparency_anchor_update ON palaco_manifest_transparency_anchor.latest;
CREATE TRIGGER guard_transparency_anchor_update BEFORE UPDATE
ON palaco_manifest_transparency_anchor.latest FOR EACH ROW
EXECUTE FUNCTION palaco_manifest_transparency_anchor.guard();
DROP TRIGGER IF EXISTS guard_transparency_anchor_delete ON palaco_manifest_transparency_anchor.latest;
CREATE TRIGGER guard_transparency_anchor_delete BEFORE DELETE
ON palaco_manifest_transparency_anchor.latest FOR EACH ROW
EXECUTE FUNCTION palaco_manifest_transparency_anchor.guard();
DROP TRIGGER IF EXISTS guard_transparency_anchor_truncate ON palaco_manifest_transparency_anchor.latest;
CREATE TRIGGER guard_transparency_anchor_truncate BEFORE TRUNCATE
ON palaco_manifest_transparency_anchor.latest FOR EACH STATEMENT
EXECUTE FUNCTION palaco_manifest_transparency_anchor.guard();
