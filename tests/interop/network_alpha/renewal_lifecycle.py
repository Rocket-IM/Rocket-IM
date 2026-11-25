"""公开对象生命周期与真实同名账号的不同Service/设备空间，含迟到回调和本地销钥。"""
import json
import shutil
import time
import secrets
from pathlib import Path
from harness import Worker, require, wait, node_binary, persistent_keychain
from types import SimpleNamespace
from business_faults import FaultProxy


def run(lab):
    def delayed():
        a,b=lab.workers
        for mode in ('late_success','late_failure'):
            a.call('disconnect');a.call('authFault',mode=mode,count=1)
            lab.auto(0,timeout=5000);wait(lambda:lab.stats(0)['held']==1,'host callback held')
            before=b.call('state');a.call('disconnect');a.call('events')
            a.call('authRelease');wait(lambda:lab.stats(0)['active']==0,'late host result settled')
            require(a.call('network')['connection']=='offline' and not a.call('events'),'late completion cannot reconnect or emit')
            require(b.call('state')==before,'cancel A cannot write B')
        # Rust超时取消旧请求，宿主故意忽略signal；第二次正常认证不能被迟到失败撤回。
        a.call('authFault',mode='late_failure',count=1);start=len(lab.stats(0)['calls'])
        lab.auto(0,timeout=250);wait(lambda:len(lab.stats(0)['calls'])>=start+2,'timeout second attempt');lab.online(0)
        a.call('authRelease');wait(lambda:lab.stats(0)['active']==0,'late failure settled after renewal')
        require(a.call('network')['connection']=='online','late failure cannot block newer credential')
        _,sent=lab.send(0,'late-result-safe');wait(lambda:lab.status(0,'late-result-safe','delivered'),'send after late failure');lab.proof('late-result-safe',sent)
    lab.case('disconnect_timeout_late_success_failure_no_resurrection',delayed)

    def callback_and_call_cancel():
        a,b=lab.workers;a.call('disconnect');a.call('authFault',mode='hang',count=1)
        lab.auto(0,timeout=30000);wait(lambda:lab.stats(0)['active']==1,'blocked callback running')
        identity=a.call('state')['identity'];other=b.call('state')['identity']
        a.call('cancelInFlight',expected='cancelled_unknown');a.call('closeKeep')
        wait(lambda:lab.stats(0)['active']==0,'caller cancel aborts callback')
        require(not a.call('alive')['alive'],'cancel reaped Rust child')
        require(b.call('state')['identity']==other,'cancelled A leaves B valid')
        lab.restart_worker(0);lab.setup(0);require(lab.workers[0].call('state')['identity']==identity,'cancel original identity');lab.auto(0);lab.online(0)
    lab.case('caller_cancel_pending_callback_bounded_process_cleanup',callback_and_call_cancel)

    def cancel_http():
        for operation in ('disconnect','closeKeep'):
            a=lab.workers[0];a.call('disconnect')
            proxy=FaultProxy(SimpleNamespace(endpoint=lab.business_endpoint,ssl=lab.ssl,env=lab.env),'timeout',delay_seconds=2)
            try:
                lab.setup(0,endpoint=proxy.endpoint);lab.auto(0,timeout=30000)
                wait(lambda:proxy.count==1 and lab.stats(0)['pending_http']==1,'real in-flight business HTTP')
                start=time.monotonic();a.call(operation)
                require(time.monotonic()-start<5,'bounded '+operation+' during HTTP')
                wait(lambda:lab.stats(0)['pending_http']==0 and lab.stats(0)['active']==0,'HTTP callback resources released')
                if operation=='closeKeep':
                    require(not a.call('alive')['alive'],'HTTP close child reaped');lab.restart_worker(0)
            finally:proxy.close()
            lab.setup(0);lab.auto(0);lab.online(0)
    lab.case('disconnect_close_abort_actual_in_flight_business_http',cancel_http)

    def storage_gate():
        original=lab.workers[0];directory=lab.root/'auth-storage-gate';directory.mkdir();(directory/'path').mkdir();(directory/'path/node').symlink_to(node_binary())
        shutil.copytree(original.directory/'node_modules',directory/'node_modules')
        for name in ('network-worker.mjs','renewal-provider.mjs'):shutil.copy2(original.directory/name,directory/name)
        keychain=directory/'lab-dedicated.keychain-db';password=secrets.token_hex(32)
        require(persistent_keychain.run({'op':'create','keychain':str(keychain),'password':password})['status']==0,'new auth storage keychain');lab.keychains.append(keychain)
        clone=Worker(directory,{**original.options,'path':str(directory/'encrypted.db'),'keychain':str(keychain),'create':True})
        try:
            clone.call('initialize');clone.call('authSetup',config={'endpoint':lab.business_endpoint,'session':lab.sessions[0],'device':'device-0','ca':str(Path(lab.env['directory'])/'ca.pem')})
            clone.call('authFault',mode='hang',count=1);clone.call('autoConnect',options=lab.auto_options[0]);wait(lambda:clone.call('authStats')['active']==1,'callback pending before storage denial')
            persistent_keychain.run({'op':'lock','keychain':str(keychain)})
            wait(lambda:clone.call('authStats')['active']==0,'network error cancels dropped owner callback')
            require(clone.call('authStats')['aborted']==1,'storage denial emits cancellation')
            events=clone.call('events');require(any(e['kind']=='network_error' for e in events),'explicit access error')
            require(persistent_keychain.run({'op':'unlock','keychain':str(keychain),'password':password})['status']==0,'unlock owned test keychain')
            require(clone.call('network')['connection']=='offline','runtime dropped network owner')
        finally:
            persistent_keychain.run({'op':'unlock','keychain':str(keychain),'password':password});clone.close()
    lab.case('storage_gate_failure_cancels_pending_authentication_owner',storage_gate)

    clones=[]
    try:
        def scope_isolation():
            original=lab.workers[0]
            for field in ('service','device'):
                directory=lab.root/('same-account-'+field);directory.mkdir();(directory/'path').mkdir();(directory/'path/node').symlink_to(node_binary())
                # 相同真实Release安装树，公开open创建独立数据空间，不通过替换测试标签冒充切换。
                shutil.copytree(original.directory/'node_modules',directory/'node_modules')
                for name in ('network-worker.mjs','renewal-provider.mjs'):shutil.copy2(original.directory/name,directory/name)
                options={**original.options,'scope':{**original.options['scope'],field:'other-'+field},'path':str(directory/'encrypted.db'),'create':True}
                clone=Worker(directory,options);clones.append(clone);clone.call('initialize');clone.options['create']=False
                clone.call('authSetup',config={'endpoint':lab.business_endpoint,'session':lab.sessions[0],'device':'device-0',
                    'other':{'session':lab.sessions[0],'device':'device-0'},'ttl':30,'ca':str(Path(lab.env['directory'])/'ca.pem')})
                clone.call('authFault',mode='wrong_token_identity',count=1)
                clone.call('autoConnect',options=lab.auto_options[0])
                blocked=wait(lambda:(s if (s:=clone.call('network'))['connection']=='blocked' else False),'same-account '+field+' rejected')
                require(blocked['error']['code']=='identity_mismatch','Service session rejects falsely labelled token')
                require(clone.call('state')['scope']==options['scope'],'actual independent public scope')
                require(clone.call('history')['items']==[],'no foreign history injected')
                clone.call('disconnect')
            require(lab.workers[1].call('state')['identity']==lab.materials[1]['identity'],'B unchanged across scopes')
        lab.case('same_account_other_service_device_real_objects_token_rejection',scope_isolation)

        def close_and_switch():
            old=lab.workers[0];old.call('disconnect');old.call('authFault',mode='late_success',count=1)
            lab.auto(0,timeout=30000);wait(lambda:lab.stats(0)['held']==1,'uncooperative callback pending')
            original=old.call('state')['identity'];old.call('events');start=time.monotonic();old.call('closeKeep')
            require(time.monotonic()-start<5 and not old.call('alive')['alive'],'close bounded without awaiting host')
            newer=Worker(old.directory,old.options);lab.workers[0]=newer;lab.setup(0)
            require(newer.call('state')['identity']==original,'new public object retains original identity')
            lab.auto(0);lab.online(0);old.call('authRelease');wait(lambda:old.call('authStats')['active']==0,'old promise settled')
            require(not old.call('events') and not old.call('alive')['alive'],'old object cannot emit into new object')
            old.close();_,sent=lab.send(0,'new-object-safe');wait(lambda:lab.status(0,'new-object-safe','delivered'),'new lifecycle message');lab.proof('new-object-safe',sent)
        lab.case('close_ignoring_signal_new_object_late_success_stays_invalid',close_and_switch)

        def logout():
            a,b=lab.workers;a.call('disconnect');a.call('authFault',mode='late_failure',count=1)
            lab.auto(0,timeout=30000);wait(lambda:lab.stats(0)['held']==1,'logout callback pending')
            other=b.call('state');clone_identities=[w.call('state') for w in clones]
            start=time.monotonic();a.call('logoutKeep')
            require(time.monotonic()-start<5 and not a.call('alive')['alive'],'logout bounded with uncooperative callback')
            a.call('events');a.call('authRelease');wait(lambda:lab.stats(0)['active']==0,'late logout failure handled')
            require(not a.call('events'),'no event after local logout')
            require(b.call('state')==other,'logout does not delete B identity/history')
            for worker,state in zip(clones,clone_identities):require(worker.call('state')==state,'same account other Service/device keys survive logout')
            lab.send(1,'after-a-logout');wait(lambda:lab.status(1,'after-a-logout','accepted'),'B continues to real Service after A logout')
            require(not lab.status(1,'after-a-logout','delivered'),'no fabricated delivery to exited A')
            # 独立进程真正重新open已退出的原库，必须拒绝而非悄悄重建。
            script=lab.root/'logout-reopen.mjs'
            entry=(a.directory/'node_modules/@rocket-im/desktop-dev/dist/index.js').as_uri()
            script.write_text("import {PersistentDevice} from "+json.dumps(entry)+";\nimport {readFile} from 'node:fs/promises';\ntry {const d=await PersistentDevice.open(JSON.parse(await readFile(process.argv[2],'utf8')));await d.close();process.exit(2);} catch(e){if(e.code!=='logged_out')process.exit(3);console.log('PASS');}\n")
            lab.command([node_binary(),script,a.directory/'open.json'],lab.root,'logout-reopen')
        lab.case('actual_logout_cancels_auth_preserves_other_account_service_device',logout)
    finally:
        for clone in clones:clone.close()
    lab.report['final_authentication_stats']=[lab.stats(i) for i in range(2)]
    lab.snapshot_secrets()
