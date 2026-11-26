-- PALACO INDUSTRIE v2.8: defense-in-depth monotonic UPDATE guard.
-- DRAFT / CI ONLY. Administrator must review before a separate deployment.
-- A restricted runtime role must NOT own this schema/table/function.
CREATE OR REPLACE FUNCTION palaco_continuity.reject_floor_regression()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.epoch < OLD.epoch OR
     NEW.minimum_last_seen_ms < OLD.minimum_last_seen_ms THEN
    RAISE EXCEPTION 'PALACO_CONTINUITY_REGRESSION'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.namespace IS DISTINCT FROM OLD.namespace THEN
    RAISE EXCEPTION 'PALACO_CONTINUITY_NAMESPACE_IMMUTABLE'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS reject_floor_regression
  ON palaco_continuity.floor_highwater;
CREATE TRIGGER reject_floor_regression
BEFORE UPDATE ON palaco_continuity.floor_highwater
FOR EACH ROW EXECUTE FUNCTION palaco_continuity.reject_floor_regression();

-- The owner-only DDL above is not an access grant. Runtime DML privileges
-- must be independently provisioned; no runtime CREATE/ALTER/DROP/INSERT.
-- IMPORTANT: privileged role with DDL or superuser rights can still disable
-- triggers / restore backups. PostgreSQL is not a hardware anti-rollback root.
