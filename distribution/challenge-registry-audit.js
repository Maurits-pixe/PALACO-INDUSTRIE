'use strict';

const NS = /^[a-z][a-z0-9._-]{2,79}$/;
const HEX = /^[a-f0-9]{64}$/;

function response(findings, counts = null) {
  return Object.freeze({
    schemaVersion: 'palaco.distribution.challenge-registry-audit.v1',
    readiness: findings.length ? 'BLOCKED' : 'REGISTRY_AUDIT_MATCH',
    authorization: 'DENY', go13: 'HOLD',
    mayAdvance: false, mayRestore: false, mayRotate: false,
    mayInstall: false, mayPublish: false,
    counts: counts && Object.freeze(counts),
    findings: Object.freeze(findings)
  });
}

/**
 * Read-only SQLite audit. minimumLastSeenMs must be supplied by an external,
 * authenticated, rollback-resistant authority. This function cannot attest
 * to that source or protect against restoring both database and bound.
 */
function auditDurableChallengeRegistry(db, { minimumLastSeenMs, maxRows = 100000 } = {}) {
  const findings = [];
  if (!Number.isSafeInteger(minimumLastSeenMs) || minimumLastSeenMs < 0)
    findings.push('INDEPENDENT_CLOCK_FLOOR_UNAVAILABLE');
  if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 1000000)
    findings.push('INVALID_ROW_LIMIT');
  if (findings.length) return response(findings);
  try {
    const check = db.prepare('PRAGMA quick_check').all();
    if (check.length !== 1 || check[0].quick_check !== 'ok')
      findings.push('SQLITE_INTEGRITY_FAILED');
    const clockRows = db.prepare('SELECT singleton, last_seen_ms FROM distribution_challenge_clock').all();
    if (clockRows.length !== 1 || clockRows[0].singleton !== 1 ||
        !Number.isSafeInteger(clockRows[0].last_seen_ms) ||
        clockRows[0].last_seen_ms < minimumLastSeenMs)
      findings.push('CLOCK_FLOOR_MISMATCH');
    const size = db.prepare('SELECT COUNT(*) AS n FROM distribution_challenges').get().n;
    if (!Number.isSafeInteger(size) || size > maxRows) {
      findings.push('REGISTRY_ROW_LIMIT_EXCEEDED');
      return response(findings);
    }
    const rows = db.prepare('SELECT challenge_hash, namespace, expires_at_ms, status FROM distribution_challenges').all();
    let pending = 0;
    let consumed = 0;
    for (const row of rows) {
      if (typeof row.challenge_hash !== 'string' || !HEX.test(row.challenge_hash) ||
          typeof row.namespace !== 'string' || !NS.test(row.namespace) ||
          !Number.isSafeInteger(row.expires_at_ms) || row.expires_at_ms < 0 ||
          (row.status !== 'pending' && row.status !== 'consumed')) {
        findings.push('INVALID_REGISTRY_RECORD');
        break;
      }
      if (row.status === 'pending') pending++;
      else consumed++;
    }
    return response(findings, { pending, consumed, total: rows.length });
  } catch (_) {
    return response([...findings, 'REGISTRY_AUDIT_STORAGE_UNAVAILABLE']);
  }
}

module.exports = { auditDurableChallengeRegistry };
