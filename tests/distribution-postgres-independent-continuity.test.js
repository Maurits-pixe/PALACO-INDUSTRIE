'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresIndependentContinuity, UPDATE_SQL } =
  require('../distribution/postgres-independent-continuity');

function store() {
  let persisted = { epoch: 5, floor: 1000 };
  const history = [];
  const query = async request => {
    history.push(request);
    const [namespace, epoch, floor] = request.values;
    if (namespace !== 'palaco.registry' ||
        epoch < persisted.epoch || floor < persisted.floor) {
      return { rowCount: 0, rows: [] };
    }
    persisted = { epoch, floor };
    return { rowCount: 1,
      rows: [{epoch: String(epoch), minimum_last_seen_ms: String(floor)}] };
  };
  return {query, history, state: () => ({...persisted})};
}
const signal = () => new AbortController().signal;

test('parameterized exact-match compare-and-advance is accepted', async () => {
  const s = store();
  const authority=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:s.query
  });
  assert.equal(await authority.advance(6,1100,signal()),true);
  assert.deepEqual(s.state(),{epoch:6,floor:1100});
  assert.deepEqual(s.history[0].values,['palaco.registry',6,1100]);
  assert.match(UPDATE_SQL,/UPDATE palaco_continuity\.floor_highwater/);
  assert.doesNotMatch(UPDATE_SQL,/\bINSERT\b|\bON CONFLICT\b/i);
});
test('restarted adapter rejects rollback held by same independent store', async () => {
  const s=store();
  const first=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:s.query
  });
  assert.equal(await first.advance(8,2000,signal()),true);
  const restarted=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:s.query
  });
  assert.equal(await restarted.advance(7,2000,signal()),false);
  assert.equal(await restarted.advance(9,1999,signal()),false);
  assert.equal(await restarted.advance(9,2100,signal()),true);
  assert.deepEqual(s.state(),{epoch:9,floor:2100});
});
test('non-boolean or malformed SQL responses fail closed', async () => {
  const cases=[
    {rowCount:0,rows:[]},
    {rowCount:1,rows:[]},
    {rowCount:1,rows:[{epoch:'7',minimum_last_seen_ms:'900'}]},
    {rowCount:2,rows:[{epoch:'7',minimum_last_seen_ms:'1100'}]},
    null
  ];
  for (const response of cases) {
    const authority=createPostgresIndependentContinuity({
      namespace:'palaco.registry',query:async()=>response
    });
    assert.equal(await authority.advance(7,1100,signal()),false);
  }
});
test('transport failures and aborted queries cannot grant continuity', async () => {
  const failed=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:async()=>{throw Error('db disconnected');}
  });
  await assert.rejects(()=>failed.advance(7,1100,signal()),/db disconnected/);
  let complete;
  const adapter=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:()=>new Promise(resolve=>{complete=resolve;})
  });
  const controller=new AbortController();
  const pending=adapter.advance(7,1100,controller.signal);
  controller.abort();
  complete({rowCount:1,rows:[{epoch:'7',minimum_last_seen_ms:'1100'}]});
  assert.equal(await pending,false);
});
test('unsafe input rejected before database query', async () => {
  let called=0;
  const adapter=createPostgresIndependentContinuity({
    namespace:'palaco.registry',query:async()=>{called++;return {rowCount:1,rows:[]};}
  });
  assert.equal(await adapter.advance(-1,1,signal()),false);
  assert.equal(await adapter.advance(1,Number.MAX_SAFE_INTEGER+1,signal()),false);
  assert.equal(called,0);
});
test('missing query or namespace fails at construction',()=>{
  assert.throws(()=>createPostgresIndependentContinuity({namespace:'palaco.registry'}),TypeError);
  assert.throws(()=>createPostgresIndependentContinuity({namespace:'*',query:async()=>null}),TypeError);
});
