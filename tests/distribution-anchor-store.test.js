'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const { generateKeyPairSync, sign } = require('node:crypto');
const { digestSnapshot } = require('../distribution/trust-continuity');
const { checkpointSigningPayload } = require('../distribution/authenticated-checkpoint');
const { initializeAnchorSchema, commitVerifiedAnchor } = require('../distribution/anchor-store');

const root = generateKeyPairSync('ed25519');
const signing = generateKeyPairSync('ed25519');
const roots = [{ keyId: 'root-test', enabled: true, revoked: false,
  publicKeyPem: root.publicKey.export({ type: 'spki', format: 'pem' }) }];
const snapshot = { schemaVersion: 'palaco.distribution.trust.v1',
  complete: true, revocationsChecked: true, keys: [{
    keyId: 'package-test', enabled: true, revoked: false,
    publicKeyPem: signing.publicKey.export({ type: 'spki', format: 'pem' }) }] };
const checkpoint = (seq, previous) => ({
  schemaVersion: 'palaco.distribution.checkpoint.v1',
  sequence: seq, previousDigest: previous, digest: digestSnapshot(snapshot)
});
const endorsement = cp => ({
  algorithm: 'Ed25519', keyId: 'root-test',
  signature: sign(null, checkpointSigningPayload(cp), root.privateKey).toString('base64')
});
function setup(provision = true) {
  const db = new DatabaseSync(':memory:');
  initializeAnchorSchema(db);
  if (provision) db.prepare('INSERT INTO distribution_trust_anchors VALUES (?, ?, ?)')
    .run('palaco.one', 4, 'a'.repeat(64));
  return db;
}
const advance = (db, cp, signed = endorsement(cp), keys = roots) =>
  commitVerifiedAnchor(db, 'palaco.one', snapshot, cp, signed, keys);

test('valid signed successor advances once and replay fails', () => {
  const db = setup();
  try {
    const cp = checkpoint(5, 'a'.repeat(64));
    const accepted = advance(db, cp);
    assert.equal(accepted.readiness, 'ANCHOR_COMMITTED');
    assert.equal(accepted.authorization, 'DENY');
    assert.equal(accepted.mayInstall, false);
    assert.equal(db.prepare('SELECT sequence FROM distribution_trust_anchors').get().sequence, 5);
    assert.equal(advance(db, cp).readiness, 'BLOCKED');
  } finally { db.close(); }
});

test('missing provisioned anchor cannot silently bootstrap', () => {
  const db = setup(false);
  try {
    const cp = checkpoint(5, 'a'.repeat(64));
    assert.equal(advance(db, cp).readiness, 'BLOCKED');
    assert.equal(db.prepare('SELECT COUNT(*) n FROM distribution_trust_anchors').get().n, 0);
  } finally { db.close(); }
});

test('bad signature, revoked authority and sequence skip leave anchor unchanged', () => {
  const db = setup();
  try {
    const cp = checkpoint(5, 'a'.repeat(64));
    const invalid = { ...endorsement(cp), signature: 'A'.repeat(86) + '==' };
    assert.equal(advance(db, cp, invalid).readiness, 'BLOCKED');
    assert.equal(advance(db, cp, endorsement(cp),
      [{ ...roots[0], revoked: true }]).readiness, 'BLOCKED');
    const skipped = checkpoint(7, 'a'.repeat(64));
    assert.equal(advance(db, skipped).readiness, 'BLOCKED');
    assert.equal(db.prepare('SELECT sequence FROM distribution_trust_anchors').get().sequence, 4);
  } finally { db.close(); }
});

test('changed predecessor and invalid namespace block transaction', () => {
  const db = setup();
  try {
    const cp = checkpoint(5, 'b'.repeat(64));
    assert.equal(advance(db, cp).readiness, 'BLOCKED');
    assert.equal(commitVerifiedAnchor(db, '../bad', snapshot, cp, endorsement(cp), roots).readiness, 'BLOCKED');
    assert.equal(db.prepare('SELECT sequence FROM distribution_trust_anchors').get().sequence, 4);
  } finally { db.close(); }
});

test('closed database cannot claim successful storage', () => {
  const db = setup();
  db.close();
  const cp = checkpoint(5, 'a'.repeat(64));
  assert.equal(advance(db, cp).readiness, 'BLOCKED');
});
