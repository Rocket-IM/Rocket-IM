"""M01只读取本轮合成秘密；报告仅保留摘要、类别和命中位置。"""

import base64
import hashlib
import json
import shutil
import subprocess

from .fixture import ACCOUNTS, check, identity


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sample_devices(lab, phase):
    samples = getattr(lab, "secret_samples", [])
    for device in ACCOUNTS:
        destination = lab.directory / "client-samples" / f"{device}-{phase}"
        destination.mkdir(parents=True, mode=0o700)
        for filename in ("device.key", "state.enc"):
            shutil.copy2(lab.directory / device / filename, destination / filename)
        samples.append({"name": f"{device}-{phase}", "directory": str(destination),
                        "context": {"service": lab.service, "account": identity(device)["account_id"],
                                    "device": device}})
    lab.secret_samples = samples


def scan(lab, name, surfaces, *, plaintexts=(), markers=()):
    check(bool(surfaces), "不能以空观测集合验收")
    files = [{"label": item["label"], "path": item["path"]} for item in surfaces]
    sources = [lab.directory / d / filename for d in ACCOUNTS for filename in ("device.key", "state.enc")]
    sources += [lab.directory / "client-samples" / item["name"] / filename
                for item in lab.secret_samples for filename in ("device.key", "state.enc")]
    before = {str(p.relative_to(lab.directory)): sha(p) for p in sources}
    request = {"root": str(lab.directory), "devices": lab.secret_samples, "files": files,
               "plaintexts": list(plaintexts), "markers": list(markers)}
    result = subprocess.run([str(lab.secret_observer)], input=json.dumps(request),
                            capture_output=True, text=True, timeout=120)
    lab.process_count += 1
    evidence = {"name": name, "exit_code": result.returncode,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
                "stderr_sha256": hashlib.sha256(result.stderr.encode()).hexdigest(),
                "source_sha256_before": before,
                "source_sha256_after": {str(p.relative_to(lab.directory)): sha(p) for p in sources},
                "surface_kinds": {item["label"]: item["kind"] for item in surfaces}}
    lab.case_evidence.setdefault("scans", []).append(evidence)
    reply = json.loads(result.stdout)
    evidence["observer"] = reply
    check(result.returncode == 0 and reply.get("ok") is True, "秘密观测器未成功，不能接受空扫描")
    check(evidence["source_sha256_before"] == evidence["source_sha256_after"], "观察器修改了设备或取样文件")
    check(len(reply["result"]["surfaces"]) == len(surfaces), "观测器遗漏输入观测面")
    return reply["result"]


def hit_surfaces(result, category=None):
    return [s for s in result["surfaces"]
            if any(category is None or h["category"] == category for h in s["hits"])]


def credential_checks(lab):
    # 只在本轮随机凭证和Service自有测试钥范围内读取，不查用户Keychain或生产环境。
    values = [(f"bearer-{device}", token.encode()) for device, token in lab.tokens.items()]
    values += [("controller-bearer", lab.controller_token.encode()),
               ("service-signing-key", lab.receipt_key.read_bytes())]
    markers = [{"name": name, "base64": base64.b64encode(raw).decode()} for name, raw in values]
    allowed = {"http_request", "http_request_body", "server_fixture", "service_key"}
    strict = [s for s in lab.surfaces if s["kind"] not in allowed]
    observed = scan(lab, "credentials-forbidden-surfaces", strict, markers=markers)
    check(not hit_surfaces(observed), "响应/数据库/日志/备份出现原凭证或私钥")
    inputs = [s for s in lab.surfaces if s["kind"] in allowed]
    positive = scan(lab, "credentials-declared-inputs", inputs, markers=markers)
    hits = {h["device"] for s in positive["surfaces"] for h in s["hits"] if h["category"] == "marker"}
    check(hits == {name for name, _ in values}, "未观测到全部预期凭证/Service钥输入，不能混称不存在")
    check(all(h["category"] == "marker" for s in positive["surfaces"] for h in s["hits"]),
          "预期凭证输入混入客户端密码秘密")
    lab.case_evidence["credential_scope"] = {"expected_input_markers": sorted(hits),
        "allowed_kinds": sorted(allowed), "forbidden_surface_count": len(strict)}
