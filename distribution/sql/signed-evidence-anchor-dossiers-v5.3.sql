-- v5.3 opt-in external transfer dossier. Apply only after v5.0 + v5.1
-- schemas in an independently controlled PostgreSQL database.
CREATE TABLE IF NOT EXISTS palaco_signed_evidence_anchor.transfer_dossiers(
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence>=3),
 nonce text NOT NULL CHECK(nonce ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 handoff_digest text NOT NULL CHECK(handoff_digest ~ '^[a-f0-9]{64}$'),
 handoff jsonb NOT NULL CHECK(jsonb_typeof(handoff)='object'),
 recipient_receipt jsonb NOT NULL CHECK(jsonb_typeof(recipient_receipt)='object'),
 PRIMARY KEY(namespace,sequence),
 UNIQUE(namespace,nonce),
 UNIQUE(namespace,handoff_digest),
 FOREIGN KEY(namespace,sequence)
  REFERENCES palaco_signed_evidence_anchor.transfer_receipts(namespace,sequence)
);
-- v5.1's generic monotone-head trigger is inappropriate for immutable receipt
-- records. Explicitly prevent ANY UPDATE (even valid-looking sequence updates).
CREATE OR REPLACE FUNCTION palaco_signed_evidence_anchor.reject_receipt_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'external receipt evidence is immutable'
 USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS guard_anchor_receipt_mutation
 ON palaco_signed_evidence_anchor.transfer_receipts;
CREATE TRIGGER guard_anchor_receipt_mutation
BEFORE UPDATE OR DELETE ON palaco_signed_evidence_anchor.transfer_receipts
FOR EACH ROW EXECUTE FUNCTION palaco_signed_evidence_anchor.reject_receipt_mutation();
DROP TRIGGER IF EXISTS guard_anchor_receipt_truncate
 ON palaco_signed_evidence_anchor.transfer_receipts;
CREATE TRIGGER guard_anchor_receipt_truncate
BEFORE TRUNCATE ON palaco_signed_evidence_anchor.transfer_receipts
FOR EACH STATEMENT EXECUTE FUNCTION palaco_signed_evidence_anchor.reject_receipt_mutation();
DROP TRIGGER IF EXISTS deny_anchor_dossier_mutation
 ON palaco_signed_evidence_anchor.transfer_dossiers;
CREATE TRIGGER deny_anchor_dossier_mutation
BEFORE UPDATE OR DELETE ON palaco_signed_evidence_anchor.transfer_dossiers
FOR EACH ROW EXECUTE FUNCTION palaco_signed_evidence_anchor.reject_receipt_mutation();
DROP TRIGGER IF EXISTS deny_anchor_dossier_truncate
 ON palaco_signed_evidence_anchor.transfer_dossiers;
CREATE TRIGGER deny_anchor_dossier_truncate
BEFORE TRUNCATE ON palaco_signed_evidence_anchor.transfer_dossiers
FOR EACH STATEMENT EXECUTE FUNCTION palaco_signed_evidence_anchor.reject_receipt_mutation();
