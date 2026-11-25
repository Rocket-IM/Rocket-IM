#!/usr/bin/env python3
"""仅测试包装器：确定的事务入口屏障及合成业务授权R0撤销。"""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import sys
import threading
import time
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"poc/network-relay"));sys.path.insert(0,str(ROOT/"tests/interop"))
from network_poc import first_trust_relay as original
from contract import fields, validate_id
from storage import Store, revoke_device

class Controls(original.FirstTrustControls):
    def execute(self,store,db,token,req):
        if req.get("action")!="key_package_revoke":return super().execute(store,db,token,req)
        super().execute(store,db,token,{"action":"stats"})
        fields(req,("action","account_id","device_id"))
        pair=tuple(validate_id(req[k]) for k in ("account_id","device_id"))
        revoke_device(db,pair)
        return {"status":"synthetic_authority_r0_revoked","device":list(pair)}

def main():
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument("--lifecycle-barrier-directory",required=True)
    args,remaining=parser.parse_known_args();path=Path(args.lifecycle_barrier_directory)
    if "--enable-test-controls" not in remaining:parser.error("必须启用测试控制器")
    original_transaction=Store.transaction
    @contextmanager
    def transaction(self):
        if (path/"armed").exists():
            ready=path/(str(os.getpid())+"-"+str(threading.get_ident())+".ready");ready.touch()
            deadline=time.monotonic()+10
            while (path/"armed").exists() and not ready.with_suffix(".release").exists():
                if time.monotonic()>deadline:raise TimeoutError("测试事务屏障未释放")
                time.sleep(.01)
        with original_transaction(self) as db:yield db
    Store.transaction=transaction;original.FirstTrustControls=Controls
    sys.argv=[sys.argv[0],*remaining];original.main()
if __name__=="__main__":main()
