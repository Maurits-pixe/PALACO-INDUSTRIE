'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {receiptChain,createReceiptSuccessionVerifier}=
 require('../distribution/receipt-succession-verifier');
const scope='palaco.registry';
const entries=[
 {sequence:'11',nonce:'nonce-11',handoff_digest:'a'.repeat(64),recipient_id:'operator-a'},
 {sequence:'12',nonce:'nonce-12',handoff_digest:'b'.repeat(64),recipient_id:'operator-a'}
];
const chain=receiptChain(entries,{namespace:scope,firstSequence:11});
const adapter=(rows=entries,root=chain)=>createReceiptSuccessionVerifier({
 namespace:scope,firstSequence:11,
 archiveQuery:async()=>({rowCount:rows.length,rows}),
 anchorQuery:async()=>({rowCount:1,rows:[{
  sequence:String(root.sequence),chain_digest:root.digest
 }]})
});
test('two chronological receipts match independent root without granting authority',async()=>{
 const result=await adapter().verify();
 assert.equal(result.readiness,'RECEIPT_SUCCESSION_VERIFIED_NON_AUTHORIZING');
 assert.equal(result.authorization,'DENY');assert.equal(result.go13,'HOLD');
 assert.equal(result.mayRestore,false);assert.equal(result.mayAdvance,false);
 assert.equal(result.count,2);assert.ok(Object.isFrozen(result));
});
test('stale restored backup and mutated receipt digest fail against external root',async()=>{
 for(const rows of [
  entries.slice(0,1),
  [entries[0],{...entries[1],handoff_digest:'c'.repeat(64)}],
  [entries[0],{...entries[1],nonce:'another-nonce'}]
 ])assert.deepEqual((await adapter(rows).verify()).findings,
  ['RECEIPT_CHAIN_ANCHOR_MISMATCH']);
});
test('out-of-order, duplicate nonce, skip, duplicate digest and bad ID fail',()=>{
 for(const rows of [
  [...entries].reverse(),
  [entries[0],{...entries[1],nonce:entries[0].nonce}],
  [entries[0],{...entries[1],sequence:'13'}],
  [entries[0],{...entries[1],handoff_digest:entries[0].handoff_digest}],
  [entries[0],{...entries[1],recipient_id:'bad space'}],
  [{...entries[0],sequence:'10'},entries[1]]
 ])assert.equal(receiptChain(rows,{namespace:scope,firstSequence:11}),null);
});
test('missing independent anchor, disconnected archive and malformed reply fail closed',async()=>{
 for(const source of [
  {archiveQuery:async()=>{throw Error('offline');}},
  {anchorQuery:async()=>{throw Error('offline');}},
  {anchorQuery:async()=>({rowCount:0,rows:[]})},
  {archiveQuery:async()=>({rowCount:2,rows:[]})}
 ]){
  const verifier=createReceiptSuccessionVerifier({
   namespace:scope,firstSequence:11,
   archiveQuery:async()=>({rowCount:2,rows:entries}),
   anchorQuery:async()=>({rowCount:1,rows:[{sequence:'12',chain_digest:chain.digest}]}),
   ...source
  });
  assert.equal((await verifier.verify()).readiness,'BLOCKED');
 }
});
test('forged same-provider arrangement and invalid chronology are invalid construction',()=>{
 const query=async()=>({rowCount:0,rows:[]});
 for(const invalid of [
  {namespace:scope,firstSequence:11,archiveQuery:query,anchorQuery:query},
  {namespace:scope,firstSequence:1,archiveQuery:query,anchorQuery:()=>{}},
  {namespace:'bad namespace',firstSequence:11,archiveQuery:query,anchorQuery:()=>{}}
 ])assert.throws(()=>createReceiptSuccessionVerifier(invalid),TypeError);
});
test('abort signal refuses read-only verification and no database write is exposed',async()=>{
 const abort=new AbortController();abort.abort();
 const verifier=adapter();
 assert.equal((await verifier.verify(abort.signal)).readiness,'BLOCKED');
 assert.equal(typeof verifier.advance,'undefined');
 assert.equal(typeof verifier.query,'undefined');
});
