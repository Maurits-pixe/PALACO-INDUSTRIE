-- v6.1 disposable CI audit store. Production must provision a separate
-- restricted principal and durable, independently retained audit records.
CREATE SCHEMA IF NOT EXISTS palaco_proof_verification_audit;
CREATE TABLE IF NOT EXISTS palaco_proof_verification_audit.events(
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 principal_id text NOT NULL CHECK(principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$'),
 request_id text CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$'),
 request_digest text CHECK(request_digest ~ '^[a-f0-9]{64}$'),
 timestamp_ms bigint NOT NULL CHECK(timestamp_ms>=0),
 readiness text NOT NULL CHECK(readiness ~ '^[A-Z_]{3,100}$'),
 finding text CHECK(finding ~ '^[A-Z_]{3,100}$'),
 authorization text NOT NULL DEFAULT 'DENY' CHECK(authorization='DENY'),
 go13 text NOT NULL DEFAULT 'HOLD' CHECK(go13='HOLD')
);
CREATE OR REPLACE FUNCTION palaco_proof_verification_audit.deny_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'verification audit is immutable' USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS deny_proof_audit_change ON palaco_proof_verification_audit.events;
CREATE TRIGGER deny_proof_audit_change BEFORE UPDATE OR DELETE
ON palaco_proof_verification_audit.events FOR EACH ROW
EXECUTE FUNCTION palaco_proof_verification_audit.deny_mutation();
DROP TRIGGER IF EXISTS deny_proof_audit_truncate ON palaco_proof_verification_audit.events;
CREATE TRIGGER deny_proof_audit_truncate BEFORE TRUNCATE
ON palaco_proof_verification_audit.events FOR EACH STATEMENT
EXECUTE FUNCTION palaco_proof_verification_audit.deny_mutation();
