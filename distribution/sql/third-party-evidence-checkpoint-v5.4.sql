-- v5.4 THIRD independently governed database; never the same
-- operational owner/backups as the source and external anchor in production.
CREATE SCHEMA IF NOT EXISTS palaco_third_witness;
CREATE TABLE IF NOT EXISTS palaco_third_witness.checkpoints(
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence>=2),
 chain_digest text NOT NULL CHECK(chain_digest ~ '^[a-f0-9]{64}$'),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>=0),
 observer_id text NOT NULL CHECK(observer_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 signature text NOT NULL CHECK(signature ~ '^[A-Za-z0-9+/]{86}==$'),
 PRIMARY KEY(namespace,sequence),
 UNIQUE(namespace,chain_digest)
);
CREATE OR REPLACE FUNCTION palaco_third_witness.forbid_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'third-party signed checkpoint is append-only'
 USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS third_checkpoint_no_update_delete
 ON palaco_third_witness.checkpoints;
CREATE TRIGGER third_checkpoint_no_update_delete
BEFORE UPDATE OR DELETE ON palaco_third_witness.checkpoints
FOR EACH ROW EXECUTE FUNCTION palaco_third_witness.forbid_mutation();
DROP TRIGGER IF EXISTS third_checkpoint_no_truncate
 ON palaco_third_witness.checkpoints;
CREATE TRIGGER third_checkpoint_no_truncate
BEFORE TRUNCATE ON palaco_third_witness.checkpoints
FOR EACH STATEMENT EXECUTE FUNCTION palaco_third_witness.forbid_mutation();
-- Cryptographic Ed25519 validation is intentionally in the independent
-- read-only verifier, not in this table's SQL constraints.
