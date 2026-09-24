"""M11.a：已有客户端快照与Relay数据库不能由另一Service范围复用。"""

import hashlib
import subprocess
import sys

from .fixture import ACCOUNTS, ROOT, check


def storage(pair):
    records = pair.evidence.setdefault("storage_rejections", [])
    for source_label, source, target_label, target in pair.directions():
        for device in ACCOUNTS:
            for operation, fields in (
                ("wire_inspect", {}),
                ("wire_send", {"logical_message_id": "wrong_storage", "attempt_id": "P1",
                               "payload": "synthetic-wrong-storage"}),
            ):
                label = f"storage/{source_label}->{target_label}/{device}/{operation}"
                before = pair.capture()
                # 保留目标实例的service/account/device，只将目录指向源实例已有快照。
                error = target.rust(device, operation, expected_exit=1,
                                    directory=str(source.directory / device), **fields)
                records.append({"label": label, "kind": "client_snapshot",
                                "stored_service": source.service,
                                "requested_service": target.service, "device": device,
                                "operation": operation, "error": error})
                check(error["code"] == "snapshot_load", "其他Service范围未在快照认证处拒绝")
                pair.unchanged(before, label)

        label = f"storage/{source_label}->{target_label}/relay_startup"
        before = pair.capture()
        command = [sys.executable, "-B", str(ROOT / "poc/network-relay/server.py"),
                   "--database", str(target.directory / "relay.sqlite"),
                   "--fixture", str(source.fixture_path), "--port", "0", "--enable-test-controls"]
        check(source.permission_verifier and source.receipt_signer,
              "跨实例数据库验证需要明确的公开验证程序与Service回执签名程序")
        command.extend(["--permission-verifier", str(source.permission_verifier),
                        "--receipt-signer", str(source.receipt_signer),
                        "--receipt-key", str(source.receipt_key)])
        source.process_count += 1
        result = subprocess.run(command, text=True, capture_output=True, timeout=15)
        error = "已有数据库服务实例不匹配"
        records.append({"label": label, "kind": "relay_database",
                        "stored_service": target.service, "requested_service": source.service,
                        "exit_code": result.returncode, "stdout_empty": not result.stdout.strip(),
                        "error": error if error in result.stderr else "unexpected_startup_failure",
                        "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest()})
        check(result.returncode == 1, "跨实例数据库启动未以显式失败退出")
        check(not result.stdout.strip(), "跨实例数据库启动不应输出ready或其他成功结果")
        check(error in result.stderr, "跨实例数据库启动没有在Service身份校验处拒绝")
        pair.unchanged(before, label)
