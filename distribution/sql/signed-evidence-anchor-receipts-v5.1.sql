-- v5.1: external full-evidence root receipts live in the independent
-- PostgreSQL anchor database, not in the primary evidence store.
-- Privileged administrator provisions schema and restricted role separately.
CREATE TABLE IF NOT EXISTS palaco_signed_evidence_anchor.transfer_receipts(
 namespace text NOT NULL CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence>=3),
 nonce text NOT NULL CHECK(nonce ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 handoff_digest text NOT NULL CHECK(handoff_digest ~ '^[a-f0-9]{64}$'),
 recipient_id text NOT NULL CHECK(recipient_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$'),
 sender_signature jsonb NOT NULL CHECK(jsonb_typeof(sender_signature)='object'),
 receipt_signature jsonb NOT NULL CHECK(jsonb_typeof(receipt_signature)='object'),
 PRIMARY KEY(namespace,sequence),
 UNIQUE(namespace,nonce),
 UNIQUE(namespace,handoff_digest)
);
DROP TRIGGER IF EXISTS guard_anchor_receipt_mutation
 ON palaco_signed_evidence_anchor.transfer_receipts;
CREATE TRIGGER guard_anchor_receipt_mutation
BEFORE UPDATE OR DELETE ON palaco_signed_evidence_anchor.transfer_receipts
FOR EACH ROW EXECUTE FUNCTION palaco_signed_evidence_anchor.guard();
DROP TRIGGER IF EXISTS guard_anchor_receipt_truncate
 ON palaco_signed_evidence_anchor.transfer_receipts;
CREATE TRIGGER guard_anchor_receipt_truncate
BEFORE TRUNCATE ON palaco_signed_evidence_anchor.transfer_receipts
FOR EACH STATEMENT EXECUTE FUNCTION palaco_signed_evidence_anchor.guard();
