"""签名版本切换的真实进程生命周期；调用者准备并验证签名，本模块不改 ACL。"""

import json
from pathlib import Path

from anchor_support import download, execute, process, snapshot, status
from crypto_support import digest, execute as crypto_execute, send_action, success
from download_support import saved
from protected_cases import Cases as ProtectionCases
from protected_support import Fixture, redact
from rebuild_support import committed, metrics
from signing_lifecycle_cases import RecoveryCases
from support import require, sha, utc_now, write_json

CASE_NAMES = (
    "upgrade_state_and_bidirectional", "mixed_rebuild_upgrade", "upgraded_cold_lock",
    "upgraded_warm_lock", "upgraded_missing_storage_key", "upgraded_missing_trust",
    "committed_receive_upgrade_recovery", "unresolved_upgrade_recovery",
)


class LifecycleCases(RecoveryCases, ProtectionCases):
    def __init__(self, v1, v2, directory, commands):
        super().__init__(v1, directory, commands)
        self.v1, self.v2 = v1, v2

    def fixture(self, name=None, device="alice-device"):
        directory = self.directory / name if name else self.directory
        # 先注册后初始化，使钥匙串创建后发生的异常仍进入本轮清理。
        fixture = Fixture.__new__(Fixture)
        self.fixtures.append(fixture)
        Fixture.__init__(fixture, self.v1, directory, self.commands, device)
        return fixture

    def switch(self, fixture, binaries=None):
        binaries = binaries or self.v2
        require(fixture.helper == binaries[2], "版本切换改变了固定 helper 路径")
        fixture.binary, fixture.native, fixture.protection = binaries[0], binaries[1], binaries[4]

    def cleanup(self):
        records = []
        for fixture in self.fixtures:
            if not hasattr(fixture, "keychain") or not fixture.keychain.exists():
                continue
            record = {"keychain": str(fixture.keychain), "locked": False}
            try:
                fixture.ctl("keychain_lock")
                record["locked"] = True
            except Exception as error:
                record["error"] = f"{type(error).__name__}: {error}"
            records.append(record)
        return records

    def send_to_peer(self, client, peer, number):
        text = f"签名升级真实发送🙂{number}"
        outgoing = committed(execute(client, f"upgrade-send-{number}", send_action(
            f"upgrade-attempt-{number}", f"upgrade-out-{number}", text)), "send")
        require(success(peer.request("peer_receive", envelope=outgoing))["text"] == text,
                "不同进程对端无法解密升级版本发送的密文")
        return digest(outgoing["ciphertext"])

    def upgrade_state_and_bidirectional(self):
        fixture = self.fixture()
        fixture.bootstrap(bind=False)
        fixture.native = self.v2[1]
        with self.native(fixture) as native:
            native_pid = native.process.pid
            identity_reply = crypto_execute(native, "initialize", {"op": "initialize"})
            require(committed(identity_reply, "initialize", cached=True) == fixture.identity,
                    "v2 原生初始化入口没有读取 v1 保存的同一身份")
        fixture.native = self.v1[1]
        fixture.bind()
        with fixture.peer() as peer:
            peer_pid = peer.process.pid
            with fixture.probe() as old:
                old_pid = old.process.pid
                data = fixture.setup(old, peer, records=2)
                saved(download(old, data["records"]), 2, 0, 2)
                first = committed(process(old, 1, "upgrade-process-1"), "receive")
                require(first["message"]["text"] == data["texts"][0], "v1 首条消息没有实际解密")
                outgoing_v1 = self.send_to_peer(old, peer, 1)
                before = snapshot(old)
            self.switch(fixture)
            with fixture.probe() as upgraded:
                upgraded_pid = upgraded.process.pid
                require(upgraded_pid != old_pid, "升级没有启动独立进程")
                opened = snapshot(upgraded)
                require(opened == before, "v2 启动改变了身份、provider、已保存记录或游标")
                identity = self.still_identity(fixture, upgraded, evidence=True)
                reply = upgraded.request("received", sequence="1")
                require(success(reply) == first and reply["events"] == [], "升级未精确读取 v1 已提交结果")
                metrics(reply)
                second = committed(process(upgraded, 2, "upgrade-process-2"), "receive")
                require(second["message"]["text"] == data["texts"][1], "v2 未处理 v1 保存的原始下载")
                outgoing_v2 = self.send_to_peer(upgraded, peer, 2)
                incoming = success(peer.request("peer_send", message_id="upgrade-in-3", text="升级后的真实接收🙂3"))
                saved(download(upgraded, [{"sequence": "3", "envelope": incoming}]), 3, 2, 1)
                third = committed(process(upgraded, 3, "upgrade-process-3"), "receive")
                require(third["message"]["text"] == "升级后的真实接收🙂3", "升级后新密文未实际解密")
                after = snapshot(upgraded)
                status(upgraded)
            protection_audit = fixture.ctl("audit", paths=[str(fixture.database)])
            require(protection_audit["result"]["no_secret_matches"], "升级后的受保护库包含未保护审计样本")
            self.switch(fixture, self.v1)
            with fixture.probe() as old_again:
                rollback_pid = old_again.process.pid
                require(snapshot(old_again) == after, "同 DR 旧版不能读取升级后精确状态")
                self.still_identity(fixture, old_again)
                reply = old_again.request("received", sequence="3")
                require(success(reply) == third and reply["events"] == [], "旧版未读到升级后原结果")
                metrics(reply)
        return {"pids": {"v1": old_pid, "v2": upgraded_pid, "v2_native": native_pid,
                         "v1_after_v2": rollback_pid, "peer": peer_pid},
                "identity": identity, "v1_snapshot": before, "v2_open_snapshot": opened,
                "v2_final_snapshot": after, "outgoing_ciphertext_digests": [outgoing_v1, outgoing_v2],
                "original_download_processed_after_upgrade": True,
                "v2_protection_audit": protection_audit["result"],
                "v1_same_dr_still_reads_v2_state": True,
                "limitation": "相同指定要求的旧程序仍可访问；签名 ACL 不提供程序版本防回滚。"}

    def upgraded_cold_lock(self):
        fixture = self.fixture()
        fixture.bootstrap()
        fixture.group("upgrade-cold", history=True)
        with fixture.probe() as old:
            before = snapshot(old)
        self.switch(fixture)
        initial_hash = sha(fixture.database)
        fixture.ctl("keychain_lock")
        error = self.refused(fixture)
        self.unchanged(fixture, initial_hash)
        fixture.ctl("keychain_unlock")
        with fixture.probe() as upgraded:
            require(snapshot(upgraded) == before, "v2 解锁重开没有保留原状态")
            identity = self.still_identity(fixture, upgraded, evidence=True)
        return {"error": error, "locked_database_sha256": initial_hash,
                "database_unchanged_while_locked": True, "identity": identity}

    def upgraded_warm_lock(self):
        fixture = self.fixture()
        fixture.bootstrap()
        fixture.group("upgrade-warm", history=True)
        with fixture.probe() as old:
            before = snapshot(old)
        self.switch(fixture)
        with fixture.probe() as upgraded:
            require(snapshot(upgraded) == before, "升级预检改变了已保存状态")
            initial_hash = sha(fixture.database)
            fixture.ctl("keychain_lock")
            locked = self.blocked(upgraded)
            self.unchanged(fixture, initial_hash)
            fixture.ctl("keychain_unlock")
            paused = self.blocked(upgraded)
            self.unchanged(fixture, initial_hash)
            with fixture.probe() as reopened:
                require(snapshot(reopened) == before, "新进程恢复后改变了锁定前状态")
                self.unchanged(fixture, initial_hash)
                identity = self.still_identity(fixture, reopened, evidence=True)
                require(snapshot(reopened) == before, "恢复后的缓存身份请求改变了业务状态")
                pids = [upgraded.process.pid, reopened.process.pid]
        return {"pids": pids, "locked_errors": locked, "same_instance_after_unlock_errors": paused,
                "database_unchanged_during_blocked_and_read_phases": True, "identity": identity,
                "close_succeeded_for_paused_instance": True}

    def missing_item(self, trust):
        fixture = self.fixture()
        fixture.bootstrap()
        fixture.group("upgrade-missing", history=True)
        self.switch(fixture)
        before = sha(fixture.database)
        with fixture.probe() as upgraded:
            fixture.ctl("key_delete", trust=trust)
            warm_errors = self.blocked(upgraded)
            self.unchanged(fixture, before)
        errors = [self.refused(fixture), self.refused(fixture)]
        absent = fixture.ctl("key_delete", expected=1, trust=trust)
        require(absent.get("ok") is False and absent.get("result") is None
                and absent.get("error", {}).get("paused") is True,
                "失败重开自动重建了缺失的钥匙串项")
        self.unchanged(fixture, before)
        return {"missing_item": "trust" if trust else "database_key", "warm_errors": warm_errors,
                "cold_errors": errors, "item_still_absent": True, "database_unchanged": True,
                "database_sha256": before}

    def upgraded_missing_storage_key(self):
        return self.missing_item(False)

    def upgraded_missing_trust(self):
        return self.missing_item(True)


def run_lifecycle(v1_binaries, v2_binaries, directory, commands):
    """逐项失败后继续；返回可并入主报告的证据，保留独立报告和脱敏进程日志。"""
    versions = [tuple(Path(path).resolve() for path in items) for items in (v1_binaries, v2_binaries)]
    require(all(len(items) == 5 and all(path.is_file() for path in items) for items in versions),
            "生命周期验证需要两组已准备的五个程序")
    v1, v2 = versions
    require(v1[2] == v2[2], "helper 必须使用同一固定路径")
    for index in (0, 1, 3, 4):
        require(v1[index].name == v2[index].name and sha(v1[index]) != sha(v2[index]),
                "v1/v2 必须为四个同名但字节不同的真实签名程序")
    output = Path(directory).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = {"status": "RUNNING", "started_at": utc_now(), "cases": [],
              "binaries_sha256": {str(path): sha(path) for paths in versions for path in paths},
              "signed_identity_requirement": "调用者须单独核验签名者、identifier 与 DR；本模块不修改 ACL。",
              "not_tested": ["本8项不含anchor_clear提交后锁定窗口；该窗口由同run的独立late-recovery报告验证",
                             "正式发行身份、系统信任与公证保障取决于主签名报告，不能从自签实验推导"]}
    for name in CASE_NAMES:
        case_directory = output / name
        case_directory.mkdir(mode=0o700)
        case = {"name": name, "status": "RUNNING", "started_at": utc_now(), "command_offset": len(commands)}
        report["cases"].append(case)
        write_json(output / "lifecycle-report.json", redact(report))
        fixture = LifecycleCases(v1, v2, case_directory, commands)
        try:
            case["evidence"] = redact(getattr(fixture, name)())
            case["status"] = "PASS"
        except Exception as error:
            case.update(status="FAIL", error=f"{type(error).__name__}: {error}")
        finally:
            case["cleanup"] = fixture.cleanup()
            if any(not item["locked"] for item in case["cleanup"]):
                case.update(status="FAIL", cleanup_error="本场景实验钥匙串未全部锁定")
            case.update(finished_at=utc_now(), command_count=len(commands) - case["command_offset"])
            entries = commands[case["command_offset"]:]
            case["pids"] = sorted({item["pid"] for item in entries if item.get("pid") is not None})
            write_json(case_directory / "case.json", redact(case))
            write_json(output / "lifecycle-report.json", redact(report))
            with (output / "commands.jsonl").open("w") as target:
                for item in commands:
                    target.write(json.dumps(redact(item), ensure_ascii=False) + "\n")
        print(json.dumps({"case": name, "status": case["status"], "error": case.get("error")}), flush=True)
    report["counts"] = {"planned": len(CASE_NAMES), "total": len(report["cases"]),
                        "passed": sum(case["status"] == "PASS" for case in report["cases"])}
    report["binaries_unchanged"] = all(sha(Path(path)) == value for path, value in report["binaries_sha256"].items())
    report["status"] = "PASS" if report["counts"]["passed"] == len(CASE_NAMES) and report["binaries_unchanged"] else "FAIL"
    report["finished_at"] = utc_now()
    write_json(output / "lifecycle-report.json", redact(report))
    return report
