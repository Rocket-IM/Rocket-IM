import { PersistentDevice, SdkError } from '@rocket-im/desktop-dev';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const [manifest,output]=process.argv.slice(2),cases=[];
const jobs=JSON.parse(await readFile(manifest,'utf8'));
for(const job of jobs) {
  const options={path:job.target.path,scope:{service:'test',account:'alice',device:'one'},upgrade:true};let d;
  try {
    if(job.name==='legacy-init') {
      await assert.rejects(()=>PersistentDevice.open({...options,upgrade:false}),e=>e.code==='migration_required');
      d=await PersistentDevice.open(options);
      await assert.rejects(()=>d.recoverRequest('target',job.action),e=>e.code==='successor_required');
      await assert.rejects(()=>d.recovery({kind:'begin',request_id:'target',action:job.action}),e=>e.code==='identity_evidence_missing');
      assert.equal((await d.request('target')).status,'pending');assert.equal((await d.state()).identity,null);
      await assert.rejects(()=>d.initialize('different'),e=>e.code==='operation_pending');
    } else {
      if(job.name==='legacy-wrong-scope') options.scope.account='wrong';
      await assert.rejects(()=>PersistentDevice.open(options),e=>e instanceof SdkError && e.code===(job.name==='legacy-wrong-scope'?'scope_mismatch':'store_invalid'));
      assert.equal(createHash('sha256').update(await readFile(job.target.path)).digest('hex'),job.sha256);
    }
    cases.push({name:job.name,status:'PASS',kind:'negative-only'});
  } catch(error) {cases.push({name:job.name,status:'FAIL',error:String(error.stack??error)});await writeFile(output,JSON.stringify({status:'FAIL',cases},null,2));throw error;}
  finally {await d?.close();}
}
await writeFile(output,JSON.stringify({status:'PASS_SCOPED',cases},null,2));console.log(JSON.stringify({status:'PASS_SCOPED',cases}));
