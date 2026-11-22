'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const { auditDurableChallengeRegistry } = require('../distribution/challenge-registry-audit');

function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE distribution_challenge_clock(singleton INTEGER PRIMARY KEY, last_seen_ms INTEGER NOT NULL) STRICT');
  db.exec('CREATE TABLE distribution_challenges(challenge_hash TEXT PRIMARY KEY, namespace TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, status TEXT NOT NULL) STRICT');
  db.prepare('INSERT INTO distribution_challenge_clock VALUES(1, ?)').run(1500);
  return db;
}
function insert(db, status, suffix = 'a') {
  db.prepare('INSERT INTO distribution_challenges VALUES(?,?,?,?)')
    .run(suffix.repeat(64), 'palaco.one', 2000, status);
}
test('consistent persisted registry produces non-authorizing assessment', () => {
  const db = fixture();
  try {
    insert(db, 'pending', 'a'); insert(db, 'consumed', 'b');
    const r = auditDurableChallengeRegistry(db, { minimumLastSeenMs: 1400 });
    assert.equal(r.readiness, 'REGISTRY_AUDIT_MATCH');
    assert.deepEqual(r.counts, { pending: 1, consumed: 1, total: 2 });
    assert.equal(r.authorization, 'DENY'); assert.equal(r.go13, 'HOLD');
    assert.equal(r.mayPublish, false); assert.equal(r.mayInstall, false);
    assert.ok(Object.isFrozen(r));
  } finally { db.close(); }
});
test('missing independently sourced clock floor always blocks', () => {
  const db = fixture(); try {
    assert.ok(auditDurableChallengeRegistry(db).findings.includes('INDEPENDENT_CLOCK_FLOOR_UNAVAILABLE'));
  } finally { db.close(); }
});
test('restored clock below externally supplied floor is blocked', () => {
  const db = fixture(); try {
    assert.ok(auditDurableChallengeRegistry(db, { minimumLastSeenMs: 1600 }).findings.includes('CLOCK_FLOOR_MISMATCH'));
  } finally { db.close(); }
});
test('missing persisted clock row blocks', () => {
  const db = fixture(); try {
    db.exec('DELETE FROM distribution_challenge_clock');
    assert.equal(auditDurableChallengeRegistry(db, { minimumLastSeenMs: 0 }).readiness, 'BLOCKED');
  } finally { db.close(); }
});
test('tampered hash and status are detected', () => {
  const db = fixture(); try {
    insert(db, 'pending');
    db.exec("UPDATE distribution_challenges SET challenge_hash='wrong'");
    assert.ok(auditDurableChallengeRegistry(db, { minimumLastSeenMs: 0 }).findings.includes('INVALID_REGISTRY_RECORD'));
    db.exec("UPDATE distribution_challenges SET challenge_hash='" + 'a'.repeat(64) + "', status='forged'");
    assert.equal(auditDurableChallengeRegistry(db, { minimumLastSeenMs: 0 }).readiness, 'BLOCKED');
  } finally { db.close(); }
});
test('row-count cap blocks before fetching entire table', () => {
  const db = fixture(); try {
    insert(db, 'pending','a'); insert(db, 'consumed','b');
    assert.ok(auditDurableChallengeRegistry(db, { minimumLastSeenMs: 0, maxRows: 1 }).findings.includes('REGISTRY_ROW_LIMIT_EXCEEDED'));
  } finally { db.close(); }
});
test('missing or closed database fails closed', () => {
  const db = fixture(); db.close();
  assert.equal(auditDurableChallengeRegistry(db, { minimumLastSeenMs: 0 }).readiness, 'BLOCKED');
  assert.equal(auditDurableChallengeRegistry(null, { minimumLastSeenMs: 0 }).readiness, 'BLOCKED');
});
test('audit is read-only and cannot consume pending challenges', () => {
  const db = fixture(); try {
    insert(db, 'pending');
    auditDurableChallengeRegistry(db, { minimumLastSeenMs: 0 });
    assert.equal(db.prepare('SELECT status FROM distribution_challenges').get().status, 'pending');
  } finally { db.close(); }
});
