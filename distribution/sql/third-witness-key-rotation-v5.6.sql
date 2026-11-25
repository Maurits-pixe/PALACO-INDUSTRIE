-- PALACO INDUSTRIE v5.6, separately provisioned REVIEW archive.
-- Not a production migration or autonomous key-rotation engine.
CREATE SCHEMA IF NOT EXISTS palaco_third_witness_rotation;
CREATE TABLE IF NOT EXISTS palaco_third_witness_rotation.attestations(
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 rotation_number bigint NOT NULL CHECK(rotation_number>=1),
 previous_manifest_digest text NOT NULL CHECK(previous_manifest_digest ~ '^[a-f0-9]{64}$'),
 next_manifest_digest text NOT NULL CHECK(next_manifest_digest ~ '^[a-f0-9]{64}$'),
 transition jsonb NOT NULL CHECK(jsonb_typeof(transition)='object'),
 retiring_signature jsonb NOT NULL CHECK(jsonb_typeof(retiring_signature)='object'),
 successor_signature jsonb NOT NULL CHECK(jsonb_typeof(successor_signature)='object'),
 review_signature jsonb NOT NULL CHECK(jsonb_typeof(review_signature)='object'),
 PRIMARY KEY(namespace,rotation_number),
 UNIQUE(namespace,next_manifest_digest),
 CHECK(previous_manifest_digest<>next_manifest_digest)
);
CREATE OR REPLACE FUNCTION palaco_third_witness_rotation.reject_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'historical rotation attestation is immutable'
 USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS deny_rotation_change
 ON palaco_third_witness_rotation.attestations;
CREATE TRIGGER deny_rotation_change
BEFORE UPDATE OR DELETE ON palaco_third_witness_rotation.attestations
FOR EACH ROW EXECUTE FUNCTION palaco_third_witness_rotation.reject_mutation();
DROP TRIGGER IF EXISTS deny_rotation_truncate
 ON palaco_third_witness_rotation.attestations;
CREATE TRIGGER deny_rotation_truncate
BEFORE TRUNCATE ON palaco_third_witness_rotation.attestations
FOR EACH STATEMENT EXECUTE FUNCTION palaco_third_witness_rotation.reject_mutation();
