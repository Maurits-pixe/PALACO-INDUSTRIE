'use strict';
// This verifies a checkpoint against live PostgreSQL data. The independent
// anchor must be supplied by a DIFFERENT trust/restore domain.
const { verifyContinuityCheckpoint } = require('./continuity-checkpoint');

const READ_SQL = [
  'SELECT epoch, minimum_last_seen_ms',
  'FROM palaco_continuity.floor_highwater',
  'WHERE namespace = $1'
].join('\n');

function blocked(reason) {
  return Object.freeze({readiness:'BLOCKED',authorization:'DENY',go13:'HOLD',
    mayRestore:false,mayAdvance:false,mayInstall:false,mayPublish:false,
    findings:Object.freeze([reason])});
}

async function verifyPostgresCheckpoint(query, checkpoint, endorsement, anchor) {
  if (typeof query!=='function') return blocked('POSTGRES_QUERY_UNAVAILABLE');
  const proof=verifyContinuityCheckpoint(checkpoint,endorsement,anchor);
  if (proof.readiness!=='CHECKPOINT_VERIFIED') return proof;
  try {
    const response=await query({text:READ_SQL,values:[checkpoint.namespace]});
    if (!response || response.rowCount!==1 || !Array.isArray(response.rows) ||
        response.rows.length!==1) return blocked('POSTGRES_WITNESS_UNAVAILABLE');
    const row=response.rows[0];
    // Equality is required, not merely >=: restored PostgreSQL or a
    // checkpoint that does not correspond to this snapshot must fail closed.
    if (!row || String(row.epoch)!==String(checkpoint.epoch) ||
        String(row.minimum_last_seen_ms)!==String(checkpoint.minimumLastSeenMs))
      return blocked('POSTGRES_CHECKPOINT_MISMATCH');
    return proof;
  } catch (_) { return blocked('POSTGRES_WITNESS_UNAVAILABLE'); }
}

module.exports={READ_SQL,verifyPostgresCheckpoint};
