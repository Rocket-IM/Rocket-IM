// 实际构建模块的公开返回契约；不计算业务额度，不访问SQLite。
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const { worksetState } = await import(pathToFileURL(resolve(process.argv[2], 'dist/workset.js')).href);
function fixture() { return {phase:'prepared',workset:{version:'control-workset-v1',id:'a'.repeat(64),
  owner:{scope:{service:'test',account:'alice',device:'a1'},identity_key:'01'.repeat(32)},sdk_instance:'aa'.repeat(32),
  conversation:'chat',context:'initial',first:'1',last:'512',originals_hash:'bb'.repeat(32)}}; }
assert.equal(worksetState(null),null);
for(const phase of ['prepared','confirmed','active','settled']) {const v=fixture();v.phase=phase;assert.deepEqual(worksetState(v),v);}
const cases=[v=>{v.extra=true;},v=>{delete v.phase;},v=>{v.phase='complete';},v=>{v.workset.extra=true;},
  v=>{v.workset.version='other';},v=>{v.workset.id='a';},v=>{v.workset.owner.extra=true;},v=>{v.workset.owner.scope.extra=true;},
  v=>{v.workset.sdk_instance='AA'.repeat(32);},v=>{v.workset.first='0';},v=>{v.workset.first='01';},v=>{v.workset.first=1;},
  v=>{v.workset.last='513';},v=>{v.workset.first='2';v.workset.last='1';},v=>{v.workset.context='retired';},v=>{v.workset.originals_hash=null;}];
for(const change of cases){const v=fixture();change(v);assert.throws(()=>worksetState(v),e=>e.code==='ipc_protocol_error');}
console.log(JSON.stringify({status:'PASS',positive_phases:4,null_observation:true,invalid_cases:cases.length}));

const v2=fixture();v2.workset.version='control-workset-v2';v2.workset.previous='cc'.repeat(32);
assert.deepEqual(worksetState(v2),v2);
const chainCases=[v=>{delete v.workset.previous;},v=>{v.workset.previous=null;},v=>{v.workset.previous='';},
  v=>{v.workset.previous='CC'.repeat(32);},v=>{v.workset.version='control-workset-v1';}];
for(const change of chainCases){const v=structuredClone(v2);change(v);assert.throws(()=>worksetState(v),e=>e.code==='ipc_protocol_error');}
console.log(JSON.stringify({status:'PASS',v2:true,invalid_chain_cases:chainCases.length}));
