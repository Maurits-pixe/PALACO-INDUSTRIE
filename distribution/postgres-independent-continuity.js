'use strict';

const { createIndependentContinuityAuthority } =
  require('./independent-continuity-authority');

const UPDATE_SQL = [
  'UPDATE palaco_continuity.floor_highwater',
  'SET epoch = $2, minimum_last_seen_ms = $3',
  'WHERE namespace = $1 AND epoch <= $2 AND minimum_last_seen_ms <= $3',
  'RETURNING epoch, minimum_last_seen_ms'
].join('\n');

/**
 * PostgreSQL adapter for independently provisioned high-watermark rows.
 * Run against a SEPARATE trusted database and role. No bootstrap, INSERT,
 * fallback, key provisioning or network client is performed here.
 *
 * query must be a trusted pg-compatible client accepting
 * {text, values, signal} and return {rowCount, rows}.
 */
function createPostgresIndependentContinuity({ namespace, query } = {}) {
  if (typeof query !== 'function') {
    throw new TypeError('Trusted PostgreSQL query adapter required');
  }
  return createIndependentContinuityAuthority({
    namespace,
    compareAndAdvance: async (scope, epoch, floor, signal) => {
      if (signal.aborted) return false;
      // Numeric arguments have been validated as safe nonnegative integers
      // by the upstream authority wrapper; never interpolate SQL values.
      const result = await query({
        text: UPDATE_SQL,
        values: [scope, epoch, floor],
        signal
      });
      if (signal.aborted || !result || result.rowCount !== 1 ||
          !Array.isArray(result.rows) || result.rows.length !== 1) return false;
      // pg returns PostgreSQL int8 as text by default; compare exactly with
      // the proposed safe-integer values rather than unsafe Number coercion.
      const row = result.rows[0];
      return !!row && String(row.epoch) === String(epoch) &&
        String(row.minimum_last_seen_ms) === String(floor);
    }
  });
}

module.exports = { UPDATE_SQL, createPostgresIndependentContinuity };
