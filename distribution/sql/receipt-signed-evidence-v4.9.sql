-- PALACO INDUSTRIE v4.9: historical signed receipt evidence sidecar.
-- Admin-only provisioning. This does NOT modify v4.7 receipt issuance.
-- Restrict INSERT to a separately trusted archival process, never public HTTP.
CREATE TABLE IF NOT EXISTS palaco_incident_witness.receipt_evidence (
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence >= 2),
 nonce text NOT NULL CHECK(nonce ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 handoff_digest text NOT NULL CHECK(handoff_digest ~ '^[a-f0-9]{64}$'),
 recipient_id text NOT NULL CHECK(recipient_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 handoff jsonb NOT NULL CHECK(jsonb_typeof(handoff)='object'),
 sender_signature jsonb NOT NULL CHECK(jsonb_typeof(sender_signature)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 receipt_signature jsonb NOT NULL CHECK(jsonb_typeof(receipt_signature)='object'),
 PRIMARY KEY(namespace,sequence),
 UNIQUE(namespace,nonce),
 UNIQUE(namespace,handoff_digest),
 FOREIGN KEY(namespace,sequence)
  REFERENCES palaco_incident_witness.receipts(namespace,sequence)
);
DROP TRIGGER IF EXISTS deny_receipt_evidence_mutation ON palaco_incident_witness.receipt_evidence;
CREATE TRIGGER deny_receipt_evidence_mutation
BEFORE UPDATE OR DELETE ON palaco_incident_witness.receipt_evidence
FOR EACH ROW EXECUTE FUNCTION palaco_incident_witness.reject_removal();
DROP TRIGGER IF EXISTS deny_receipt_evidence_truncate ON palaco_incident_witness.receipt_evidence;
CREATE TRIGGER deny_receipt_evidence_truncate
BEFORE TRUNCATE ON palaco_incident_witness.receipt_evidence
FOR EACH STATEMENT EXECUTE FUNCTION palaco_incident_witness.reject_removal();
