"""持久准备的进程观察与状态断言；业务操作仍由原 Rust 和 HTTP 执行。"""

import json
import os
from pathlib import Path
import subprocess
import sys

from .fixture import check
from .reclamation_fixture import DEVICES, PreparedRequest, database, snapshot


def host(lab, mode, *, device="c1", expected_exit=0):
    config = {"mode": mode, "directory": str(lab.directory), "binary": str(lab.binary),
        "permission_verifier": str(lab.permission_verifier), "receipt_signer": str(lab.receipt_signer),
        "service": lab.service, "url": lab.url.geturl(), "token": lab.tokens[device], "device": device}
    if hasattr(lab, "configs"):
        config.update(anchor_helper=str(lab.helper), anchor_config=str(lab.configs[device]))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.Popen([sys.executable, "-m", "network_poc.reclamation_preparation_host"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    try:
        stdout, stderr = process.communicate(json.dumps(config), timeout=60)
    except BaseException:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        lab.case_evidence.setdefault("host_failures", []).append(
            {"pid": process.pid, "stdout": stdout, "stderr": stderr, "interrupted": True})
        raise
    result = json.loads(stdout) if stdout.strip() else {}
    result.update(exit_code=process.returncode, stderr=stderr)
    lab.case_evidence.setdefault("host_processes", []).append(result)
    lab.process_count += result.get("rust_process_count", 0)
    lab.http_count += result.get("http_count", 0)
    check(process.returncode == expected_exit and result.get("host_pid") == process.pid,
          f"宿主 {mode} 返回 {process.returncode}: {stderr[:500]}")
    check(not {"plan_id", "acceptance_ids", "processed_seq", "request", "receipt"} & set(result["input_keys"]),
          "新宿主恢复输入夹带观察者材料")
    return result


def state(lab):
    return {"relay": database(lab), "snapshots": {d: snapshot(lab, d) for d in DEVICES}}


def local_plan(lab, device, plan, status="prepared"):
    before, rows = snapshot(lab, device), database(lab)
    listing = lab.rust(device, "wire_reclaim_list", limit="100")
    check({"plan_id": plan, "status": status} in listing["plans"], "本机列表丢失计划或状态错误")
    recovered = lab.rust(device, "wire_reclaim_recover", plan_id=plan)
    check(recovered["status"] == status and recovered["plan_id"] == plan,
          "恢复材料未绑定原计划或阶段")
    check(snapshot(lab, device) == before and database(lab) == rows, "查询重写快照或改变 Relay")
    return recovered


def confirm_saved(lab, device, plan):
    recovered = local_plan(lab, device, plan)
    return lab.http(device, "confirm_reclaim", PreparedRequest(recovered))


def unchanged_rejection(lab, operation, code, **fields):
    before = state(lab)
    anchor = lab.rust("c1", "anchor_inspect") if hasattr(lab, "configs") else None
    error = lab.rust("c1", operation, expected_exit=1, **fields)
    check(error["code"] == code and state(lab) == before, "拒绝错误或留下部分状态")
    if anchor is not None:
        check(lab.rust("c1", "anchor_inspect") == anchor, "预约前拒绝留下新锚或推进 revision")
    lab.case_evidence.setdefault("preparation_rejections", []).append({"operation": operation,
        "fields": fields, "error": error, "before": before, "anchor_before": anchor})
