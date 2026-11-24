-- v5.0: commitment is write-once and foreign-key-bound to the
-- complete signed evidence sidecar. Provision by trusted admin only.
CREATE TABLE IF NOT EXISTS palaco_incident_witness.evidence_commitments (
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence>=2),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(namespace,sequence),
 UNIQUE(namespace,evidence_digest),
 FOREIGN KEY(namespace,sequence)
 REFERENCES palaco_incident_witness.receipt_evidence(namespace,sequence)
);
DROP TRIGGER IF EXISTS forbid_evidence_commitment_changes
 ON palaco_incident_witness.evidence_commitments;
CREATE TRIGGER forbid_evidence_commitment_changes
BEFORE UPDATE OR DELETE ON palaco_incident_witness.evidence_commitments
FOR EACH ROW EXECUTE FUNCTION palaco_incident_witness.reject_removal();
DROP TRIGGER IF EXISTS forbid_evidence_commitment_truncate
 ON palaco_incident_witness.evidence_commitments;
CREATE TRIGGER forbid_evidence_commitment_truncate
BEFORE TRUNCATE ON palaco_incident_witness.evidence_commitments
FOR EACH STATEMENT EXECUTE FUNCTION palaco_incident_witness.reject_removal();
