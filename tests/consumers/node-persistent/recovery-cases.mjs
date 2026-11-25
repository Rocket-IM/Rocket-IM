import { successor } from './recovery-support.mjs';
// 输入为另行测试构建留下的原库；此进程只安装/调用正常 Release TGZ，不调用测试程序或 SQL。
import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
const [manifest, output] = process.argv.slice(2);
const jobs = JSON.parse(await readFile(manifest,'utf8')); const cases = [];
const open = d => PersistentDevice.open({path:d.path,scope:{service:'test',account:d.account,device:'one'},upgrade:d.upgrade??false});
const denied = (fn, code) => assert.rejects(fn, e=>e instanceof SdkError && e.code===code);

for (const job of jobs) {
  let t,p;const events=[],queries=[],errors=[],pids=[];
  try {
    t=await open(job.target);p=await open(job.peer);pids.push(t.runtime.pid,p.runtime.pid);
    if (job.name==='repeat-candidate-interruption') {
      const c=new AbortController();c.abort();const before=await t.state();
      await denied(()=>t.recoverRequest('target',job.action,{signal:c.signal}),'cancelled');assert.deepEqual(await t.state(),before);
      const inflight=new AbortController();const pending=t.recovery({kind:'status'},{signal:inflight.signal});inflight.abort();
      await denied(()=>pending,'cancelled_unknown');await t.close();t=await open(job.target);pids.push(t.runtime.pid);
    }
    for (const d of [t,p]) d.subscribe(change=>{events.push(change);queries.push(d.state().then(state=>assert.ok(BigInt(state.revision)>=BigInt(change.revision))).catch(e=>errors.push(String(e))));});
    let recovered, strategy='exact';
    const status=await t.recovery({kind:'status'});
    if (status.phase!==null) { strategy='successor';await successor(t,p,job); }
    else {
      try { recovered=await t.recoverRequest('target',job.action); }
      catch(error) { if (error.code!=='successor_required') throw error; strategy='successor';await successor(t,p,job); }
    }
    if (strategy==='exact') {
      const duplicate=await t.recoverRequest('target',job.action);assert.equal(duplicate.cached,true);assert.deepEqual(duplicate.value,recovered.value);
      if (job.operation==='create') await p.joinGroup('post-join','chat',(await t.state()).identity,recovered.value.welcome);
      if (job.operation==='initialize') {
        const tm=await t.joiningMaterial(),pm=await p.joiningMaterial();
        const group=await t.createGroup('post-create','chat',pm.identity,pm.key_package);
        await p.joinGroup('post-join','chat',tm.identity,group.value.welcome);
      }
      if (job.operation==='send') await p.receive('post-original',recovered.value.envelope);
      assert.equal((await t.request('target')).status,'complete');
    } else {
      assert.equal((await t.request('target')).status,'retired');
      await denied(()=>t.recoverRequest('target',job.action),'request_retired');
      if (job.action.kind==='send') await denied(()=>t.send('reused-id',job.action.message_id,'replacement'),'message_conflict');
      if (job.name==='both-pending') assert.equal((await p.request('other-pending')).status,'retired');
    }
    assert.deepEqual((await t.state()).identity,job.fault_audit.identity);
    assert.deepEqual((await p.state()).identity,job.peer_before.identity);
    if (job.history) {
      for (const d of [t,p]) {
        assert.equal((await d.message(job.target.account,'one','old-target')).text,'old-target');
        assert.equal((await d.message(job.peer.account,'one','old-peer')).text,'old-peer');
      }
      const old=await t.request('old-target');assert.equal(old.status,'complete');
      if (strategy==='successor') await denied(()=>p.receive('retired-envelope',old.outcome.value.envelope),'context_retired');
    }
    const outgoing=await t.send('post-send','post-message','恢复后目标 → 对端');
    assert.equal((await p.receive('post-receive',outgoing.value.envelope)).value.message.text,'恢复后目标 → 对端');
    const count=(await p.state()).received_count;assert.equal((await p.receive('duplicate-message',outgoing.value.envelope)).cached,true);assert.equal((await p.state()).received_count,count);
    const reply=await p.send('post-back','post-reply','恢复后对端 → 目标');
    assert.equal((await t.receive('post-back',reply.value.envelope)).value.message.text,'恢复后对端 → 目标');
    await Promise.all(queries);assert.deepEqual(errors,[]);
    await t.close();await p.close();
    t=await open(job.target);p=await open(job.peer);pids.push(t.runtime.pid,p.runtime.pid);
    const restart=await p.send('restart','restart','再重启仍可通信');await t.receive('restart',restart.value.envelope);
    const back=await t.send('restart-back','restart-back','双向仍可通信');await p.receive('restart-back',back.value.envelope);
    cases.push({name:job.name,status:'PASS',strategy,original_status:(await t.request('target')).status,context:(await t.state()).context,
      identities_preserved:true,history_preserved:job.history,bidirectional_after_recovery:true,bidirectional_after_restart:true,events:events.map(e=>({kind:e.kind,revision:e.revision}))});
  } catch(error) {
    cases.push({name:job.name,status:'FAIL',error:String(error.stack??error)});
    await writeFile(output,JSON.stringify({status:'FAIL',cases},null,2));throw error;
  } finally {
    await Promise.allSettled([t?.close(),p?.close()]);
    for(const pid of pids) assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});
  }
  await writeFile(output,JSON.stringify({status:'RUNNING',cases},null,2));
}
const report={status:'PASS_SCOPED',cases};await writeFile(output,JSON.stringify(report,null,2));console.log(JSON.stringify({status:report.status,case_count:cases.length,report:output}));
