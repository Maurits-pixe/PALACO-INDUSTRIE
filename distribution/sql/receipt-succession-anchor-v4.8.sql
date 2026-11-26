-- v4.8 independent receipt-chain head, provision in separately controlled DB.
-- The receipt archive does NOT own this schema or its backup/restore domain.
CREATE SCHEMA IF NOT EXISTS palaco_receipt_anchor;
CREATE TABLE IF NOT EXISTS palaco_receipt_anchor.latest (
 namespace text PRIMARY KEY CHECK(namespace ~ '^[a-z][a-z0-9._-]{2,79}$'),
 sequence bigint NOT NULL CHECK(sequence >= 2),
 chain_digest text NOT NULL CHECK(chain_digest ~ '^[a-f0-9]{64}$')
);
CREATE OR REPLACE FUNCTION palaco_receipt_anchor.reject_regression()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.namespace IS DISTINCT FROM OLD.namespace
    OR NEW.sequence <> OLD.sequence+1
    OR NEW.chain_digest IS NOT DISTINCT FROM OLD.chain_digest THEN
  RAISE EXCEPTION 'receipt root regression or invalid continuation'
   USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS reject_receipt_anchor_update ON palaco_receipt_anchor.latest;
CREATE TRIGGER reject_receipt_anchor_update
BEFORE UPDATE ON palaco_receipt_anchor.latest FOR EACH ROW
EXECUTE FUNCTION palaco_receipt_anchor.reject_regression();
CREATE OR REPLACE FUNCTION palaco_receipt_anchor.reject_removal()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'receipt root deletion prohibited'
  USING ERRCODE='23514';
END;
$$;
DROP TRIGGER IF EXISTS reject_receipt_anchor_delete ON palaco_receipt_anchor.latest;
CREATE TRIGGER reject_receipt_anchor_delete
BEFORE DELETE ON palaco_receipt_anchor.latest FOR EACH ROW
EXECUTE FUNCTION palaco_receipt_anchor.reject_removal();
DROP TRIGGER IF EXISTS reject_receipt_anchor_truncate ON palaco_receipt_anchor.latest;
CREATE TRIGGER reject_receipt_anchor_truncate
BEFORE TRUNCATE ON palaco_receipt_anchor.latest FOR EACH STATEMENT
EXECUTE FUNCTION palaco_receipt_anchor.reject_removal();
