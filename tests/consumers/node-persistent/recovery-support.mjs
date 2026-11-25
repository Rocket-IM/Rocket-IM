import { SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
const denied = (fn,code) => assert.rejects(fn,e=>e instanceof SdkError && e.code===code);
export async function successor(t,p,job) {
  for (let step=0;step<14;step++) {
    let ts=await t.recovery({kind:'status'}), ps=await p.recovery({kind:'status'});
    if (ts.phase==='finished') return ts.context;
    if (ts.phase==='joining' || ts.phase==='closing' || ps.phase==='building' || ps.phase==='closing') {
      const targetStarts=ts.phase==='joining'||ts.phase==='closing';
      const initiator=targetStarts?t:p, other=targetStarts?p:t;
      const first=await initiator.recovery({kind:'close',peer_close:null});
      const second=await other.recovery({kind:'close',peer_close:first.packet});
      const third=await initiator.recovery({kind:'close',peer_close:second.packet});
      assert.equal(second.phase,'closed'); assert.equal(third.phase,'closed'); continue;
    }
    if (ts.phase===null || ts.phase==='closed') {
      ts=await t.recovery({kind:'begin',request_id:'target',action:job.action});
      assert.equal(ts.phase,'offered');
      assert.deepEqual(await t.recovery({kind:'begin',request_id:'target',action:job.action}),ts);
      continue;
    }
    if (ts.phase==='offered' && ps.context!==ts.context) {
      const identity=(await t.state()).identity;
      await denied(()=>p.recovery({kind:'accept',offer:ts.packet,peer:{...identity,scope:{...identity.scope,account:'wrong'}}}),'recovery_identity_mismatch');
      const accepted=await p.recovery({kind:'accept',offer:ts.packet,peer:identity});
      assert.equal(accepted.phase,'prepared');
      assert.deepEqual(await p.recovery({kind:'accept',offer:ts.packet,peer:identity}),accepted); continue;
    }
    if (ts.phase==='offered' && ps.phase==='prepared') {
      const ready=await t.recovery({kind:'join',approval:ps.packet});
      assert.equal(ready.phase,'ready'); assert.deepEqual(await t.recovery({kind:'join',approval:ps.packet}),ready); continue;
    }
    if (ts.phase==='ready' && ps.phase==='prepared') {
      const confirmed=await p.recovery({kind:'confirm',ready:ts.packet}); assert.ok(confirmed.commit);
      const duplicate=await p.recovery({kind:'confirm',ready:ts.packet}); assert.equal(duplicate.commit,null); assert.equal(duplicate.packet,confirmed.packet); continue;
    }
    if (ts.phase==='ready' && ps.phase==='committed') {
      const finished=await t.recovery({kind:'finish',receipt:ps.packet}); assert.ok(finished.commit);
      const duplicate=await t.recovery({kind:'finish',receipt:ps.packet}); assert.equal(duplicate.commit,null); assert.equal(duplicate.packet,finished.packet); continue;
    }
    throw new Error(`unhandled recovery phase ${ts.phase}/${ps.phase}`);
  }
  throw new Error('recovery did not finish within bounded steps');
}
