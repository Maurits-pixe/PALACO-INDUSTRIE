'use strict';
// Two GitHub Actions invocations separated by docker kill -s KILL and restart.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {createAuthorityAnchorStore}=require('../distribution/postgres-authority-anchor');

test('authority anchor survives abrupt PostgreSQL container termination', {
 skip:process.env.PALACO_TEST_POSTGRES!=='1' ||
  !['prepare','verify'].includes(process.env.PALACO_TEST_PHASE)
},async()=>{
 const {Client}=require('pg');
 const client=new Client({connectionString:process.env.PALACO_TEST_DATABASE_URL});
 await client.connect();
 try{
  const store=createAuthorityAnchorStore({namespace:'palaco.registry',
   query:args=>client.query(args)});
  const first='a'.repeat(64),second='b'.repeat(64);
  if(process.env.PALACO_TEST_PHASE==='prepare'){
   await client.query(fs.readFileSync(path.join(__dirname,
    '../distribution/sql/authority-anchor-highwater-v3.9.sql'),'utf8'));
   await client.query('TRUNCATE palaco_authority_anchor.latest');
   await client.query(
    'INSERT INTO palaco_authority_anchor.latest(namespace,revision,state_digest) VALUES($1,$2,$3)',
    ['palaco.registry',40,first]);
   // SQL is privileged only in this disposable CI stage. The real runtime
   // has no arbitrary state-write method.
   await client.query(
    'UPDATE palaco_authority_anchor.latest SET revision=$1,state_digest=$2 WHERE namespace=$3',
    [41,second,'palaco.registry']);
   assert.deepEqual(await store.latest(),{revision:41,digest:second});
  }else{
   assert.deepEqual(await store.latest(),{revision:41,digest:second});
   // A fully valid and previously signed old rotation would be rejected
   // against this persisted head, even if its local files were restored.
   await assert.rejects(client.query(
    'UPDATE palaco_authority_anchor.latest SET revision=$1,state_digest=$2 WHERE namespace=$3',
    [40,first,'palaco.registry']),err=>err.code==='23514');
   await assert.rejects(client.query(
    'UPDATE palaco_authority_anchor.latest SET revision=$1,state_digest=$2 WHERE namespace=$3',
    [43,'c'.repeat(64),'palaco.registry']),err=>err.code==='23514');
   assert.deepEqual(await store.latest(),{revision:41,digest:second});
  }
 }finally{await client.end();}
});
