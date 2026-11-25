import { PersistentDevice } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { successor } from './recovery-support.mjs';
const [manifest,output]=process.argv.slice(2);const jobs=JSON.parse(await readFile(manifest,'utf8')),cases=[];
const open=d=>PersistentDevice.open({path:d.path,scope:{service:'test',account:d.account,device:'one'}});
const denied=(fn,code)=>assert.rejects(fn,e=>e.code===code);
for(const job of jobs) {
  let t,p,second;const events=[];
  try {
    t=await open(job.target);p=await open(job.peer);t.subscribe(c=>events.push(c));p.subscribe(c=>events.push(c));
    const begin={kind:'begin',request_id:'target',action:job.action};
    if(job.name==='concurrent-offer') {
      second=await open(job.target);
      const results=await Promise.allSettled([t.recovery(begin),second.recovery(begin)]);
      const successes=results.filter(r=>r.status==='fulfilled').map(r=>r.value);
      assert.ok(successes.length>=1);
      for(const r of successes)assert.equal(r.packet,successes[0].packet);
      for(const r of results.filter(r=>r.status==='rejected'))assert.ok(['reservation_changed','storage_failure'].includes(r.reason.code));
      assert.equal(events.length,0);
      const before=await t.state();const cancelled=new AbortController();cancelled.abort();
      await denied(()=>t.recovery({kind:'status'},{signal:cancelled.signal}),'cancelled');assert.deepEqual(await t.state(),before);
      const offer=await t.recovery({kind:'status'});
      const approval=await p.recovery({kind:'accept',offer:offer.packet,peer:(await t.state()).identity});
      const ready=await t.recovery({kind:'join',approval:approval.packet});
      const receipt=await p.recovery({kind:'confirm',ready:ready.packet});
      const finishes=await Promise.allSettled([t.recovery({kind:'finish',receipt:receipt.packet}),second.recovery({kind:'finish',receipt:receipt.packet})]);
      assert.equal(finishes.filter(r=>r.status==='fulfilled' && r.value.commit!==null).length,1);
      for(const r of finishes.filter(r=>r.status==='rejected'))assert.ok(['reservation_changed','storage_failure'].includes(r.reason.code));
      assert.equal((await t.recovery({kind:'status'})).phase,'finished');
      await second.close();second=null;
    } else if(job.name==='closed-material') {
      const offer=await t.recovery(begin);const identity=(await t.state()).identity;
      const wrong=Buffer.from(offer.packet,'hex');wrong[wrong.length-4]^=1;
      await assert.rejects(()=>p.recovery({kind:'accept',offer:wrong.toString('hex'),peer:identity}));
      assert.equal((await p.recovery({kind:'status'})).phase,null);assert.equal(events.length,0);
      for(const field of ['service','account','device']) {
        await denied(()=>p.recovery({kind:'accept',offer:offer.packet,peer:{...identity,scope:{...identity.scope,[field]:'other'}}}),'recovery_identity_mismatch');
      }
      const approval=await p.recovery({kind:'accept',offer:offer.packet,peer:identity});
      // 合法 Approval 已持久，正常API不允许单方取消，避免目标已有Ready时形成分叉。
      await denied(()=>p.recovery({kind:'close',peer_close:null}),'recovery_close_not_allowed');
      const fake=Buffer.from(approval.packet,'hex');fake[fake.length-4]^=1;
      await assert.rejects(()=>t.recovery({kind:'join',approval:fake.toString('hex')}));
      assert.equal((await t.recovery({kind:'status'})).phase,'offered');assert.equal(events.length,0);
      await successor(t,p,job);
      // 已完成轮的错误材料不能重开；读取旧原件不会改变当前上下文。
      const before=await t.state();await t.recovery({kind:'inspect',context:offer.context});assert.deepEqual(await t.state(),before);
      await denied(()=>t.recovery({kind:'inspect',context:'0'.repeat(64)}),'recovery_missing');
      await denied(()=>t.recovery({kind:'close',peer_close:null}),'recovery_close_not_allowed');
    } else if(job.name==='closed-round-replay') {
      const first=await t.recovery({kind:'close',peer_close:null});
      const ack=await p.recovery({kind:'close',peer_close:first.packet});
      await t.recovery({kind:'close',peer_close:ack.packet});
      const fresh=await t.recovery(begin);
      await denied(()=>t.recovery({kind:'join',approval:job.old_approval}),'recovery_context_mismatch');
      assert.equal((await p.recovery({kind:'accept',offer:job.old_offer,peer:(await t.state()).identity})).phase,'closed');
      assert.equal((await t.recovery({kind:'status'})).packet,fresh.packet);
      await successor(t,p,job);
      await denied(()=>t.recovery({kind:'close',peer_close:ack.packet}),'recovery_material_conflict');
    } else {
      const offer=await t.recovery(begin);
      const approval=await p.recovery({kind:'accept',offer:offer.packet,peer:(await t.state()).identity});
      const ready=await t.recovery({kind:'join',approval:approval.packet});
      const committed=await p.recovery({kind:'confirm',ready:ready.packet});
      // 目标仍在Ready；对端收到坏应用密文后产生真实密码失败，开始下一恢复。
      const sent=await p.send('intermediate','intermediate','new context');
      const corrupt={...sent.value.envelope,sender_account:job.target.account,message_id:'tampered'};
      const bytes=Buffer.from(corrupt.ciphertext,'hex');bytes[bytes.length-1]^=1;corrupt.ciphertext=bytes.toString('hex');
      const action={kind:'receive',envelope:corrupt};
      await assert.rejects(()=>p.receive('target',corrupt),e=>e.paused===true);
      assert.equal((await p.request('target')).status,'pending');
      const next=await p.recovery({kind:'begin',request_id:'target',action});assert.equal(next.phase,'offered');
      const old=await p.recovery({kind:'inspect',context:ready.context});assert.equal(old.packet,committed.packet);
      await t.recovery({kind:'finish',receipt:old.packet});
      await successor(p,t,{...job,action});
    }
    const e=await t.send('advanced','advanced','安全恢复');await p.receive('advanced',e.value.envelope);
    const back=await p.send('advanced-back','advanced-back','双向确认');await t.receive('advanced-back',back.value.envelope);
    await t.close();await p.close();t=await open(job.target);p=await open(job.peer);
    const again=await p.send('advanced-restart','advanced-restart','重启');await t.receive('advanced-restart',again.value.envelope);
    cases.push({name:job.name,status:'PASS',bidirectional:true,restarted:true});
  } catch(error) {cases.push({name:job.name,status:'FAIL',error:String(error.stack??error)});await writeFile(output,JSON.stringify({status:'FAIL',cases},null,2));throw error;}
  finally {await Promise.allSettled([t?.close(),p?.close(),second?.close()]);}
}
await writeFile(output,JSON.stringify({status:'PASS_SCOPED',cases},null,2));console.log(JSON.stringify({status:'PASS_SCOPED',cases}));
