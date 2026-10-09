"""F10：明确归档来源的旧程序/旧 fixture 构造 None 快照，再执行真实升级。"""

import json
from pathlib import Path
import shutil
import subprocess
import sys

from .fixture import check
from .first_trust_evidence import digest, state
from .first_trust_fixture import reject, roundtrip
from .first_trust_session import verify_all

WORKER = r'''
import json, pathlib, sys
config = json.loads(sys.argv[1])
sys.path.insert(0, config["fixture_import_root"])
from network_poc.fixture import NetworkLab
lab = NetworkLab(config["binary"], pathlib.Path(config["directory"]), config["verifier"], config["signer"],
                 relay_entrypoint=config["relay"])
try:
    lab.initialize(permissions=True)
    packet = lab.prepare("legacy-cached")
    accepted = lab.submit(packet)
    lab.rust("a1", "wire_accept", logical_message_id="legacy-cached", attempt_id="P1",
             acceptance_receipt=accepted["acceptance_receipt"])
    data = {key:getattr(lab,key) for key in ("public","tokens","controller_token","fixture","checkpoint",
            "state_ref","relay_receipt_key","process_count","http_count")}
    data.update(packet=packet,accepted=accepted)
    output = pathlib.Path(config["control"])
    output.write_text(json.dumps(data)); output.chmod(0o600)
finally:
    lab.close()
'''


def legacy_upgrade(lab):
    check(not lab.helper and lab.old_binary and lab.old_fixture, "旧升级需要显式普通模式与归档来源")
    new_binary, new_empty = lab.binary, state(lab)
    try:
        lab.binary = lab.old_binary
        error = lab.rust("a1", "inspect", expected_exit=1)
        check(error["code"] == "state_decoding" and state(lab) == new_empty, "新 Init 未显式标记严格格式")
    finally:
        lab.binary = new_binary
    lab.case_evidence["old_reader_new_init"] = error
    lab.stop()
    root = Path(__file__).resolve().parents[3]
    old_report_path = lab.old_fixture.parents[4] / "report.json"
    old_report = json.loads(old_report_path.read_text())
    old_sources = {str(path.relative_to(lab.old_fixture.parents[3])): digest(path.read_bytes())
                   for path in lab.old_fixture.parent.glob("*.py")}
    check(all(old_report["source_sha256_before"].get(path) == value for path, value in old_sources.items()),
          "归档旧 fixture 模块与其原报告不一致")
    lab.case_evidence["legacy_fixture_source"] = {"report": str(old_report_path),
        "report_sha256": digest(old_report_path.read_bytes()), "original_status": old_report["status"],
        "modules": old_sources}
    archive = lab.directory / "legacy-source/tests/interop/network_poc"
    archive.parent.mkdir(parents=True)
    shutil.copytree(lab.old_fixture.parent, archive, ignore=shutil.ignore_patterns("__pycache__"))
    check(digest((archive / "fixture.py").read_bytes()) == digest(lab.old_fixture.read_bytes()),
          "旧 fixture 拷贝变化")
    work = lab.directory / "legacy-devices"
    control = lab.directory / "legacy-control.json"
    options = {"fixture_import_root": str(archive.parent), "binary": str(lab.old_binary),
        "verifier": str(lab.old_binary.with_name("openmls-permission-verify")),
        "signer": str(lab.old_binary.with_name("openmls-relay-receipt")), "directory": str(work),
        "relay": str(root / "poc/network-relay/server.py"), "control": str(control)}
    process = subprocess.Popen([sys.executable, "-B", "-c", WORKER, json.dumps(options)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lab.case_evidence["legacy_constructor"] = {"pid": process.pid, "binary": str(lab.old_binary),
        "fixture": str(lab.old_fixture), "fixture_sha256": digest(lab.old_fixture.read_bytes()),
        "boundary": "actual archived pre-Q01 binary plus byte-identical copied pre-Q01 fixture; synthetic pinned initial group"}
    try:
        stdout, stderr = process.communicate(timeout=120)
    except BaseException:
        process.kill(); process.communicate(timeout=5)
        raise
    lab.case_evidence["legacy_constructor"].update(exit_code=process.returncode,
        stdout_sha256=digest(stdout.encode()), stderr_sha256=digest(stderr.encode()))
    check(process.returncode == 0, "真实旧程序构造失败: " + stderr[-800:])
    saved = json.loads(control.read_text())
    for key in ("public", "tokens", "controller_token", "fixture", "checkpoint", "state_ref", "relay_receipt_key"):
        setattr(lab, key, saved[key])
    lab.process_count += saved["process_count"] + 1
    lab.http_count += saved["http_count"]
    lab.directory, lab.fixture_path = work, work / "fixture.json"
    lab.receipt_key = work / "relay-receipt.key"
    lab.relay_entrypoint, lab.relay_args = root / "poc/network-relay/server.py", ()
    lab.receipt_active = True
    lab.start()
    old_state = state(lab)
    for device in lab.public:
        result = lab.rust(device, "identity_trust_inspect")
        check(result == {"strict": True, "records": []}, "旧 pin/checkpoint 被提升为核验")
    check(state(lab) == old_state, "旧 None 查询重写快照")
    reject(lab)
    reject(lab, logical_message_id="legacy-cached", attempt_id="P1", payload="synthetic-network-legacy-cached")
    new_binary = lab.binary
    try:
        lab.binary = lab.old_binary
        lab.rust("a1", "inspect")
        check(state(lab) == old_state, "只读升级改变旧格式兼容性")
    finally:
        lab.binary = new_binary
    verify_all(lab)
    repeated = lab.rust("a1", "wire_send", logical_message_id="legacy-cached", attempt_id="P1",
                        payload="synthetic-network-legacy-cached")
    check(repeated["envelope"] == saved["packet"]["envelope"], "补核验后重建旧密文")
    roundtrip(lab, "after-legacy-verification")
    new_state = state(lab)
    try:
        lab.binary = lab.old_binary
        error = lab.rust("a1", "inspect", expected_exit=1)
        check(error["code"] == "state_decoding" and state(lab) == new_state,
              "旧程序没有拒绝新增持久核验字段或改变快照")
    finally:
        lab.binary = new_binary
    lab.case_evidence.update(legacy_none_state=old_state, verified_new_state=new_state,
                            old_reader_rejection=error, legacy_cached_envelope=saved["packet"]["envelope"])


CASES = [("Q01.F10.legacy_upgrade", legacy_upgrade)]
