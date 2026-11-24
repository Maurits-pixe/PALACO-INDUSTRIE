-- PALACO INDUSTRIE v4.7. Admin-only provisioning on separate witness DB.
-- Replay keys cannot be altered by the constrained witness writer role.
CREATE TABLE IF NOT EXISTS palaco_incident_witness.receipts (
 namespace text NOT NULL CHECK (namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 handoff_digest text NOT NULL CHECK (handoff_digest ~ '^[a-f0-9]{64}$'),
 recipient_id text NOT NULL CHECK (recipient_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 sequence bigint NOT NULL CHECK (sequence >= 2),
 PRIMARY KEY(namespace,nonce),
 UNIQUE(namespace,handoff_digest),
 UNIQUE(namespace,sequence)
);
-- The receipts table is immutable after insertion, including TRUNCATE.
DROP TRIGGER IF EXISTS deny_receipt_update_delete ON palaco_incident_witness.receipts;
CREATE TRIGGER deny_receipt_update_delete
BEFORE UPDATE OR DELETE ON palaco_incident_witness.receipts
FOR EACH ROW EXECUTE FUNCTION palaco_incident_witness.reject_removal();
DROP TRIGGER IF EXISTS deny_receipt_truncate ON palaco_incident_witness.receipts;
CREATE TRIGGER deny_receipt_truncate
BEFORE TRUNCATE ON palaco_incident_witness.receipts
FOR EACH STATEMENT EXECUTE FUNCTION palaco_incident_witness.reject_removal();
