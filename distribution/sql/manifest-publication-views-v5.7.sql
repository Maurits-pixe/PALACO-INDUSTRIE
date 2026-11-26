-- PALACO INDUSTRIE v5.7. Provision separately for EACH observer,
-- never as one common trust or backup domain in production.
CREATE SCHEMA IF NOT EXISTS palaco_manifest_publication;
CREATE TABLE IF NOT EXISTS palaco_manifest_publication.views(
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 rotation_number bigint NOT NULL CHECK(rotation_number>=1),
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 previous_manifest_digest text NOT NULL CHECK(previous_manifest_digest ~ '^[a-f0-9]{64}$'),
 observer_id text NOT NULL CHECK(observer_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>=0),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9+/]{86}==$'),
 PRIMARY KEY(namespace,rotation_number),
 CHECK(previous_manifest_digest<>manifest_digest)
);
CREATE OR REPLACE FUNCTION palaco_manifest_publication.reject_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'publication observation immutable' USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS deny_publication_view_changes ON palaco_manifest_publication.views;
CREATE TRIGGER deny_publication_view_changes BEFORE UPDATE OR DELETE
ON palaco_manifest_publication.views FOR EACH ROW
EXECUTE FUNCTION palaco_manifest_publication.reject_mutation();
DROP TRIGGER IF EXISTS deny_publication_view_truncate ON palaco_manifest_publication.views;
CREATE TRIGGER deny_publication_view_truncate BEFORE TRUNCATE
ON palaco_manifest_publication.views FOR EACH STATEMENT
EXECUTE FUNCTION palaco_manifest_publication.reject_mutation();
