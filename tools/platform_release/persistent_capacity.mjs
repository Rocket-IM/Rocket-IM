// 独立构建后的契约负例，不复制容量算法或访问数据库。
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const { capacity } = await import(pathToFileURL(resolve(process.argv[2], 'dist/capacity.js')).href);
function fixture() {
  return {
    version:'sdk-capacity-alpha2',owner:'sdk',scope:{service:'test',account:'a',device:'one'},observation_id:'a'.repeat(64),consistency:'single_sqlite_read',revision:'18446744073709551615',cursors:null,
    recovery:{pending:'none',phase:null,candidate:false,locally_authorized:false,network_phase:null},
    budgets:['requests','ordinary_messages','events','data_bytes','crypto_bytes','meta_bytes','history','archives','transitions'].map(category=>({category,unit:category.endsWith('_bytes')?'bytes':'items',used:'9007199254740993',limit:'18446744073709551615',hard_remaining:'18437736874454810622'})),
    components:['candidate_bytes','session_bytes','archives_bytes','legacy_bytes'].map(category=>({category,included_in:'meta_bytes',bytes:'0'})),
    reserve:{state:'not_enabled',protected_remaining:null,ordinary_available:null,resources:[],work:[]},
    operations:['new_send','new_receive','retry_request','recover_pending','retry_send','download','process','report','install_candidate','new_recovery','authorized_recovery','first_backup','export','import'].map(operation=>({operation,state:'requires_input',blockers:[]})),
    blockers:[],physical:{state:'unavailable',reserved:false},remote:{state:'unavailable',reserved:false},
  };
}
assert.equal(capacity(fixture()).budgets[0].used,'9007199254740993');
assert.equal(capacity(fixture()).revision,'18446744073709551615');
const changes = [
  v=>{v.extra=true;},v=>{delete v.cursors;},v=>{v.revision=1;},v=>{v.revision=null;},v=>{v.revision='01';},v=>{v.revision='-1';},v=>{v.revision='18446744073709551616';},v=>{v.revision='1e3';},
  v=>{v.scope.extra=true;},v=>{v.scope.account=null;},v=>{v.physical.reserved=null;},v=>{delete v.reserve.protected_remaining;},v=>{v.reserve.protected_remaining='0';},
  v=>{v.budgets[0].hard_remaining='0';},v=>{v.budgets.pop();},v=>{v.budgets[0]=v.budgets[1];},v=>{v.components[0].included_in='data_bytes';},v=>{v.components[0].bytes=0;},
  v=>{v.recovery.phase='unknown';},v=>{v.recovery.candidate=true;},v=>{v.recovery.locally_authorized=null;},v=>{v.operations[0].state='bounded_ready';},v=>{v.operations[0].blockers=['request_limit'];},
  v=>{v.cursors={downloaded:'0',processed:'1',reported:'0'};},v=>{v.cursors={downloaded:'1',processed:'1',reported:'2'};},
];
for (const change of changes) { const v=fixture();change(v);assert.throws(()=>capacity(v),e=>e.code==='ipc_protocol_error'); }
console.log(JSON.stringify({status:'PASS',invalid_cases:changes.length,large_integer:'uint64_lossless',database_access:false}));
function reservedFixture() {
  const v=fixture();v.reserve.state='bounded_ready';
  v.reserve.resources=v.budgets.map(b=>({category:b.category,protected_remaining:'1',ordinary_available:(BigInt(b.hard_remaining)-1n).toString()}));
  v.reserve.work=['candidate_install','send_settlement','known_control','known_report','target_install','backup_guard'].map(kind=>({kind,count:'1'}));
  v.operations.find(o=>o.operation==='retry_send').state='bounded_ready';return v;
}
assert.equal(capacity(reservedFixture()).reserve.resources[0].protected_remaining,'1');
const reservedChanges=[
  v=>{delete v.reserve.resources;},v=>{v.reserve.resources=null;},v=>{v.reserve.work[0].extra=true;},
  v=>{v.reserve.resources[0].protected_remaining='01';},v=>{v.reserve.resources[0].ordinary_available='18446744073709551616';},
  v=>{v.reserve.resources[0].protected_remaining='0';},v=>{v.reserve.work[0].count='2';},v=>{v.reserve.work.pop();},
  v=>{v.reserve.work[0].kind='new_crypto';},v=>{v.operations[0].state='bounded_ready';},v=>{v.reserve.work[1].count='0';},
];
for(const change of reservedChanges){const v=reservedFixture();change(v);assert.throws(()=>capacity(v),e=>e.code==='ipc_protocol_error');}
console.log(JSON.stringify({status:'PASS',reserved_invalid_cases:reservedChanges.length,reserved_positive:true}));
