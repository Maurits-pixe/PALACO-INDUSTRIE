'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const { generateKeyPairSync, sign } = require('node:crypto');
const { initializeDurableChallengeSchema, createDurableChallengeRegistry } =
  require('../distribution/durable-challenge-registry');
const { createPrefetchedSignedChallengeRegistry } =
  require('../distribution/prefetched-signed-challenge-registry');
const { clockFloorPayload } = require('../distribution/signed-clock-floor');
const { authorityReceiptPayload } = require('../distribution/authority-receipt');

const signer = generateKeyPairSync('ed25519');
const receiptSigner = generateKeyPairSync('ed25519');
const roots = [{ keyId: 'independent-floor', enabled: true, revoked: false,
  publicKeyPem: signer.publicKey.export({ type: 'spki', format: 'pem' }) }];
const receiptRoots = [{ keyId: 'receipt', enabled: true, revoked: false,
  publicKeyPem: receiptSigner.publicKey.export({ type: 'spki', format: 'pem' }) }];

function fixture() {
  const db = new DatabaseSync(':memory:');
  initializeDurableChallengeSchema(db);
  let time = 1000;
  const clock = () => time;
  const bootstrap = createDurableChallengeRegistry(db, { clock });
  assert.equal(bootstrap.issue('palaco.one').issued, true);
  return { db, clock, time: value => { time = value; } };
}
function floorReply(challenge, overrides = {}) {
  const floor = { schemaVersion: 'palaco.distribution.signed-clock-floor.v1',
    namespace: 'palaco.registry', epoch: 5, minimumLastSeenMs: 1000, challenge, ...overrides };
  return { floor, endorsement: { algorithm: 'Ed25519', keyId: 'independent-floor',
    signature: sign(null, clockFloorPayload(floor), signer.privateKey).toString('base64') } };
}
function authority(fetchSignedFloor) {
  return { namespace: 'palaco.registry', pinnedRoots: roots,
    minimumEpoch: 5, fetchSignedFloor };
}
function registry(f, fetchSignedFloor, extra = {}) {
  return createPrefetchedSignedChallengeRegistry(f.db, {
    floorAuthority: authority(fetchSignedFloor), clock: f.clock, ...extra
  });
}
function receipt(challenge) {
  const state = { schemaVersion: 'palaco.distribution.authority-state.v1',
    namespace: 'palaco.one', sequence: 10, digest: 'a'.repeat(64), challenge };
  return { state, endorsement: { algorithm: 'Ed25519', keyId: 'receipt',
    signature: sign(null, authorityReceiptPayload(state), receiptSigner.privateKey).toString('base64') } };
}

test('fetch takes place before the database write transaction', async () => {
  const f = fixture();
  try {
    const r = registry(f, async nonce => {
      // A nested transaction on the same connection would fail if BEGIN IMMEDIATE
      // had already been entered by the registry.
      f.db.exec('BEGIN IMMEDIATE');
      f.db.exec('ROLLBACK');
      await Promise.resolve();
      return floorReply(nonce);
    });
    assert.equal((await r.issue('palaco.one')).issued, true);
  } finally { f.db.close(); }
});

test('fresh prefetched proof can issue and consume but not grant release', async () => {
  const f = fixture();
  try {
    const r = registry(f, async nonce => floorReply(nonce));
    const issued = await r.issue('palaco.one');
    assert.equal(issued.issued, true);
    const { state, endorsement } = receipt(issued.challenge);
    const verified = await r.consume('palaco.one', issued.challenge, state,
      endorsement, receiptRoots, 10);
    assert.equal(verified.readiness, 'AUTHORITY_RECEIPT_VALID');
    assert.equal(verified.authorization, 'DENY');
    assert.equal(verified.mayPublish, false);
    assert.equal((await r.consume('palaco.one', issued.challenge, state,
      endorsement, receiptRoots, 10)).readiness, 'BLOCKED');
  } finally { f.db.close(); }
});

test('invalid floor signature blocks without creating a challenge', async () => {
  const f = fixture();
  try {
    const r = registry(f, async nonce => {
      const proof = floorReply(nonce);
      return { ...proof, endorsement: { ...proof.endorsement, signature: 'bad' } };
    });
    assert.equal((await r.issue('palaco.one')).issued, false);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM distribution_challenges').get().n, 1);
  } finally { f.db.close(); }
});

test('replayed clock proof cannot satisfy a new nonce', async () => {
  const f = fixture();
  try {
    let first;
    const r = registry(f, async nonce => first ??= floorReply(nonce));
    assert.equal((await r.issue('palaco.one')).issued, true);
    assert.equal((await r.issue('palaco.one')).issued, false);
  } finally { f.db.close(); }
});

test('floor older than stored database clock rollback bound blocks', async () => {
  const f = fixture();
  try {
    f.time(2000);
    const r = registry(f, async nonce => floorReply(nonce, { minimumLastSeenMs: 1500 }));
    assert.equal((await r.issue('palaco.one')).issued, false);
    assert.equal(f.db.prepare('SELECT last_seen_ms FROM distribution_challenge_clock')
      .get().last_seen_ms, 1000);
  } finally { f.db.close(); }
});

test('preparation failures on consume leave challenge pending', async () => {
  const f = fixture();
  try {
    const ok = registry(f, nonce => floorReply(nonce));
    const token = (await ok.issue('palaco.one')).challenge;
    const broken = registry(f, async () => { throw new Error('network down'); });
    const {state,endorsement} = receipt(token);
    assert.equal((await broken.consume('palaco.one', token, state, endorsement,
      receiptRoots, 10)).readiness, 'BLOCKED');
    assert.equal((await ok.consume('palaco.one', token, state, endorsement,
      receiptRoots, 10)).readiness, 'AUTHORITY_RECEIPT_VALID');
  } finally { f.db.close(); }
});

test('stale proof is blocked by monotonic age bound', async () => {
  const f = fixture();
  try {
    let now = 0n;
    const r = registry(f, async nonce => { now = 10_000_000n; return floorReply(nonce); },
      { maxProofAgeMs: 5, monotonicNow: () => now });
    assert.equal((await r.issue('palaco.one')).issued, false);
  } finally { f.db.close(); }
});

test('missing authority, roots or independent epoch fails closed', () => {
  const f = fixture();
  try {
    assert.throws(() => createPrefetchedSignedChallengeRegistry(f.db), TypeError);
    assert.throws(() => registry(f, () => null, {maxProofAgeMs: 0}), TypeError);
    assert.throws(() => createPrefetchedSignedChallengeRegistry(f.db, {
      floorAuthority: {...authority(() => null),minimumEpoch:null}
    }), TypeError);
  } finally { f.db.close(); }
});

test('tampered floor epoch is rejected without mutation', async () => {
  const f = fixture();
  try {
    const r = registry(f, nonce => floorReply(nonce, {epoch:4}));
    assert.equal((await r.issue('palaco.one')).issued, false);
    assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM distribution_challenges').get().n, 1);
  } finally { f.db.close(); }
});
