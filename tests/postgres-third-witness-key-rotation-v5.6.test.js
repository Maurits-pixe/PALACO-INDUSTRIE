'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign}=require('node:crypto');
const {manifestDigest}=require('../distribution/third-witness-key-history-v5.5');
const {VERSION,transitionBytes}=require('../distribution/third-witness-key-rotation-v5.6');
const {createThirdWitnessRotationAttestor}=
 require('../distribution/third-witness-rotation-attestor-v5.6');
test('restricted PostgreSQL triple-signed rotation is immutable, ordered and replay-resistant',{
 skip:process.env.PALACO_TEST_POSTGRES!=='1'
},async()=>{
 const {Client}=require('pg');
 const admin=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 let writer;
 await admin.connect();
 try{
  const sql=fs.readFileSync(path.join(__dirname,
   '../distribution/sql/third-witness-key-rotation-v5.6.sql'),'utf8');
  await admin.query(sql);
  const role='palaco_v56_rotation_reviewer';
  await admin.query("CREATE ROLE "+role+" LOGIN PASSWORD 'ci_only_v56'");
  await admin.query('REVOKE ALL ON SCHEMA palaco_third_witness_rotation FROM PUBLIC');
  await admin.query('REVOKE ALL ON palaco_third_witness_rotation.attestations FROM PUBLIC');
  await admin.query('GRANT USAGE ON SCHEMA palaco_third_witness_rotation TO '+role);
  await admin.query('GRANT SELECT,INSERT ON palaco_third_witness_rotation.attestations TO '+role);
  await admin.query('ALTER TABLE palaco_third_witness_rotation.attestations ENABLE ROW LEVEL SECURITY');
  await admin.query("CREATE POLICY rotation_read_ci ON palaco_third_witness_rotation.attestations FOR SELECT TO "+role+" USING(namespace='palaco.v56ci')");
  await admin.query("CREATE POLICY rotation_insert_ci ON palaco_third_witness_rotation.attestations FOR INSERT TO "+role+" WITH CHECK(namespace='palaco.v56ci')");
  const url=new URL(process.env.PALACO_TEST_DATABASE_URL);
  url.username=role;url.password='ci_only_v56';
  writer=new Client({connectionString:url.toString()});await writer.connect();
  const keys=Array.from({length:3},()=>generateKeyPairSync('ed25519'));
  const pem=i=>keys[i].publicKey.export({type:'spki',format:'pem'});
  const namespace='palaco.v56ci';
  const oldEpoch={observerId:'custodian',keyId:'previous-key',
   validFromMs:1000,validUntilMs:3000,enabled:true,revoked:false,
   publicKeyPem:pem(0)};
  const newEpoch={observerId:'custodian',keyId:'next-key',
   validFromMs:3000,validUntilMs:9000,enabled:true,revoked:false,
   publicKeyPem:pem(1)};
  const previousManifest={
   schemaVersion:'palaco.distribution.third-witness-key-history.v1',
   namespace,floorSequence:12,floorDigest:'a'.repeat(64),epochs:[oldEpoch]
  };
  const nextManifest={...previousManifest,epochs:[oldEpoch,newEpoch],
   floorSequence:13,floorDigest:'b'.repeat(64)};
  const transition={schemaVersion:VERSION,namespace,rotationNumber:1,
   previousManifestDigest:manifestDigest(previousManifest),
   nextManifestDigest:manifestDigest(nextManifest),
   retiringKeyId:oldEpoch.keyId,successorKeyId:newEpoch.keyId,
   rotatedAtMs:2999,authorization:'DENY',go13:'HOLD',
   purpose:'TRUST_KEY_ROTATION_NO_RELEASE'};
  const signed=(i,keyId)=>({algorithm:'Ed25519',keyId,
   signature:sign(null,transitionBytes(transition),keys[i].privateKey).toString('base64')});
  const signatures=[signed(0,'previous-key'),signed(1,'next-key'),signed(2,'review-key')];
  const policyProvider=async()=>({
   pinnedPreviousDigest:manifestDigest(previousManifest),
   trustedRotationNumber:0,
   reviewRoot:{keyId:'review-key',enabled:true,revoked:false,
    publicKeyPem:pem(2)}
  });
  const attestor=createThirdWitnessRotationAttestor({
   namespace,query:request=>writer.query(request),policyProvider
  });
  const args=[previousManifest,nextManifest,transition,...signatures];
  const forged={...signatures[2],signature:'A'.repeat(86)+'=='};
  assert.equal((await attestor.record(previousManifest,nextManifest,transition,
   signatures[0],signatures[1],forged)).readiness,'BLOCKED');
  const accepted=await attestor.record(...args);
  assert.equal(accepted.readiness,'THIRD_ROTATION_ATTESTED_NON_AUTHORIZING');
  assert.equal(accepted.authorization,'DENY');assert.equal(accepted.go13,'HOLD');
  assert.equal(accepted.mayAdvance,false);
  assert.equal((await attestor.record(...args)).readiness,'BLOCKED');
  const stored=await writer.query(
   'SELECT rotation_number,previous_manifest_digest,next_manifest_digest FROM palaco_third_witness_rotation.attestations WHERE namespace=$1',
   [namespace]);
  assert.deepEqual(stored.rows,[{
   rotation_number:'1',
   previous_manifest_digest:manifestDigest(previousManifest),
   next_manifest_digest:manifestDigest(nextManifest)
  }]);
  for(const query of [
   'DELETE FROM palaco_third_witness_rotation.attestations',
   'UPDATE palaco_third_witness_rotation.attestations SET rotation_number=2',
   'TRUNCATE palaco_third_witness_rotation.attestations',
   'ALTER TABLE palaco_third_witness_rotation.attestations DISABLE TRIGGER deny_rotation_change'
  ])await assert.rejects(writer.query(query),e=>e.code==='42501');
  await assert.rejects(admin.query(
   'DELETE FROM palaco_third_witness_rotation.attestations WHERE namespace=$1',
   [namespace]),e=>e.code==='23514');
 }finally{
  if(writer)await writer.end().catch(()=>{});
  await admin.end().catch(()=>{});
 }
});
