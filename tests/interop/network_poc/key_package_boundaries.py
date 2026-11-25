"""独立装置覆盖撤销/退役的两种提交顺序和三个到期窗口。"""
from contextlib import contextmanager
import copy
import time
from .fixture import ACCOUNTS,CONVERSATION,check,identity
from .key_package_fixture import KeyPackageLab,decode
from .first_trust_evidence import state,database

@contextmanager
def child(parent,name):
    lab=KeyPackageLab(parent.binary,parent.directory/name,parent.permission_verifier,parent.receipt_signer)
    lab.probe_binary=getattr(parent,"probe_binary",None)
    try:
        lab.initialize();yield lab
    finally:
        lab.stop();parent.case_evidence.setdefault("subcases",{})[name]=lab.case_evidence
        parent.process_count+=lab.process_count;parent.http_count+=lab.http_count


def remove_r1(lab,target="d1"):
    change=lab.rust("a1","permission_prepare",change_id="finish-r1",action={"kind":"remove_member","account_id":identity(target)["account_id"]})["change"]
    accepted=lab.http("a1","submit_permission_change",{"service_id":lab.service,"conversation_id":CONVERSATION,"change":change})
    for actor in ACCOUNTS:lab.rust(actor,"permission_recover",record={"change":change,"receipt":accepted["receipt"]})


def k10(parent):
    for order in ("revoke_claim","claim_revoke","accept_revoke","retire_claim","claim_retire"):
        with child(parent,order) as lab:
            lab.publish(count=1);lab.ready()
            proof=lab.request("a1","ordered-claim",lab.claim_action(change_id="ordered-join"))
            revoke=lambda:lab.control("key_package_revoke",**identity("d1"))
            if order=="revoke_claim":
                lab.ordered([revoke,lambda:lab.remote("a1",proof,expected=403)])
                check(lab.rows("kp_materials")[0]["state"]=="retired","撤销后材料可领")
            elif order=="claim_revoke":
                result,_=lab.ordered([lambda:lab.remote("a1",proof),revoke]);lab.response("a1",proof,result)
                candidate=lab.prepare_join("ordered-claim");before=database(lab)
                error=lab.submit_join(candidate,expected=409)
                check(error["code"]=="key_package_reuse" and database(lab)==before,"已撤销材料仍被接受或留下半状态")
                lab.remote("a1",proof,expected=403)
                lab.continued(sender="a2",recipients=("a2","b1","c1"));continue
            elif order=="accept_revoke":
                result=lab.remote("a1",proof);lab.response("a1",proof,result);candidate=lab.prepare_join("ordered-claim")
                accepted,_=lab.ordered([lambda:lab.submit_join(candidate),revoke])
                check(lab.rows("kp_materials")[0]["state"]=="accepted","撤销抹除了历史接受")
                lab.http("d1","get_join_material",{"service_id":lab.service,"conversation_id":CONVERSATION,"change_id":"ordered-join"},expected=403)
                lab.remote("a1",proof,expected=403)
                for actor in ACCOUNTS:lab.rust(actor,"permission_recover",record={"change":candidate["change"],"receipt":accepted["receipt"]})
                remove_r1(lab)
            else:
                material=lab.rows("kp_materials")[0]
                retirement=lab.request("d1","retirement",{"kind":"retire","key_package_sha256":material["hash"]})
                if order=="retire_claim":
                    _,result=lab.ordered([lambda:lab.remote("d1",retirement),lambda:lab.remote("a1",proof)])
                    check(decode(result["receipt"])["result"]["kind"]=="unavailable","退役先提交后仍可分配")
                else:
                    result,_=lab.ordered([lambda:lab.remote("a1",proof),lambda:lab.remote("d1",retirement,expected=409)])
                    check(decode(result["receipt"])["result"]["kind"]=="allocated" and lab.rows("kp_materials")[0]["state"]=="allocated","分配后被退回")
            lab.continued()


def wait_expiry(lab):
    end=max(int(p["material"]["not_after"]) for p in lab.pool()["packages"].values())
    while time.time()<end:time.sleep(.05)


def k12(parent):
    from .key_package_cases import reject_rust
    for stage in ("claimed","accept-crosses-expiry","accepted","joined"):
        with child(parent,"expiry-"+stage) as lab:
            lab.publish(count=1,ttl=10);lab.ready();proof,claim=lab.claim();candidate=lab.prepare_join()
            if stage in ("accepted","joined"):bundle=lab.accepted_bundle(candidate)
            if stage=="joined":lab.rust("d1","permission_join",**bundle)
            if stage=="accept-crosses-expiry":
                end=max(int(p["material"]["not_after"]) for p in lab.pool()["packages"].values())
                while time.time()<end-1:time.sleep(.01)
                before=database(lab);lab.control("hook",hook="delay_before_commit",delay_ms="2000")
                started=time.monotonic();error=lab.submit_join(candidate,expected=409)
                check(time.monotonic()-started>=1.8 and error["code"]=="key_package_expired","没有覆盖事务内跨到期边界")
                check(database(lab)==before,"跨期限事务留下部分接受")
                lab.continued(sender="a2",recipients=("a2","b1","c1"));continue
            wait_expiry(lab);before=database(lab)
            if stage=="claimed":
                lab.submit_join(candidate,expected=(400,409));check(database(lab)==before,"过期首次接受部分提交")
                check(lab.remote("a1",proof)==claim,"过期不能取回原领取事实")
                lab.continued(sender="a2",recipients=("a2","b1","c1"))
            elif stage=="accepted":
                check(reject_rust(lab,"d1","permission_join",**bundle)["code"]=="key_package_expired","过期首次加入未拒绝")
                check(database(lab)==before and lab.rows("kp_materials")[0]["state"]=="accepted","抹除了历史接受")
                check(lab.submit_join(candidate)["receipt"]==bundle["record"]["receipt"],"到期原接受不可查询")
                lab.continued()
            else:
                check(lab.rust("d1","permission_join",**bundle)["duplicate"],"成功加入因KP到期失效")
                lab.continued(recipients=(*ACCOUNTS,"d1"))
                forged=copy.deepcopy(bundle);value=forged["join"]["welcome"];forged["join"]["welcome"]=value[:-4]+"AAAA"
                reject_rust(lab,"d1","permission_join",**forged)
                lab.continued("after-forgery",recipients=(*ACCOUNTS,"d1"))
