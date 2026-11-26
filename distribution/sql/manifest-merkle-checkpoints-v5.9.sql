-- v5.9 signed Merkle checkpoints. Provision in separately administered
-- database. This schema is CI-only; not a production migration.
CREATE SCHEMA IF NOT EXISTS palaco_manifest_merkle_anchor;
CREATE TABLE IF NOT EXISTS palaco_manifest_merkle_anchor.checkpoints(
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 tree_size bigint NOT NULL CHECK(tree_size>=1),
 merkle_root text NOT NULL CHECK(merkle_root ~ '^[a-f0-9]{64}$'),
 observer_id text NOT NULL CHECK(observer_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>=0),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9+/]{86}==$'),
 PRIMARY KEY(namespace,tree_size)
);
CREATE OR REPLACE FUNCTION palaco_manifest_merkle_anchor.reject_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'signed merkle checkpoint immutable'
 USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS deny_merkle_checkpoint_change
 ON palaco_manifest_merkle_anchor.checkpoints;
CREATE TRIGGER deny_merkle_checkpoint_change BEFORE UPDATE OR DELETE
ON palaco_manifest_merkle_anchor.checkpoints FOR EACH ROW
EXECUTE FUNCTION palaco_manifest_merkle_anchor.reject_mutation();
DROP TRIGGER IF EXISTS deny_merkle_checkpoint_truncate
 ON palaco_manifest_merkle_anchor.checkpoints;
CREATE TRIGGER deny_merkle_checkpoint_truncate BEFORE TRUNCATE
ON palaco_manifest_merkle_anchor.checkpoints FOR EACH STATEMENT
EXECUTE FUNCTION palaco_manifest_merkle_anchor.reject_mutation();
