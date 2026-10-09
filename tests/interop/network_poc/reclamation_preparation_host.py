"""独立宿主进程只经本机列举/恢复取得材料；不读观察者记录或 Relay 数据库。"""

import http.client
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlparse

from .fixture import check
from .reclamation_fixture import (PreparedRequest, ReclamationAnchorLab, ReclamationLab,
                                  digest, snapshot)


def main():
    config = json.load(sys.stdin)
    required = {"mode", "directory", "binary", "permission_verifier", "receipt_signer",
                "service", "url", "token", "device"}
    optional = {"anchor_helper", "anchor_config"} if "anchor_helper" in config else set()
    check(set(config) == required | optional, "恢复宿主收到了原计划/选择/游标/请求/许可")
    arguments = [config[name] for name in ("binary", "directory", "permission_verifier", "receipt_signer")]
    lab = (ReclamationAnchorLab(*arguments, config["anchor_helper"])
           if optional else ReclamationLab(*arguments, service=config["service"]))
    device, mode = config["device"], config["mode"]
    if optional:
        lab.configs[device] = Path(config["anchor_config"])
    lab.case_evidence = {}
    lab.url, lab.tokens = urlparse(config["url"]), {device: config["token"]}
    report = {"host_pid": os.getpid(), "mode": mode, "input_keys": sorted(config),
              "snapshot_before": snapshot(lab, device)}
    exit_code = 0
    try:
        listing = lab.rust(device, "wire_reclaim_list", limit="1")
        check(len(listing["plans"]) == 1 and not listing["has_more"], "限定宿主要求恰好一项本机计划")
        plan = listing["plans"][0]
        recovered = lab.rust(device, "wire_reclaim_recover", plan_id=plan["plan_id"])
        report.update(listing=listing, recovered_status=recovered["status"])
        if mode in ("confirm", "confirm_lost", "apply_lost"):
            check(recovered["status"] == "prepared", "确认恢复没有取得已保存准备材料")
            request = PreparedRequest(recovered)
            report.update(request_json_sha256=digest(request.request_json.encode()),
                          original_p=request["processed_seq"])
            try:
                confirmed = lab.http(device, "confirm_reclaim", request)
                check(mode != "confirm_lost", "预设确认中断未触发")
            except (http.client.RemoteDisconnected, ConnectionResetError) as error:
                check(mode == "confirm_lost", "发生非预期 HTTP 中断")
                report.update(disconnect=type(error).__name__, event="LOST_CONFIRM_RESPONSE")
                exit_code = 91
            if mode == "confirm":
                report.update(recovered=recovered, confirmed=confirmed)
            elif mode == "apply_lost":
                check(confirmed["status"] == "ready", "未取得许可却尝试本机应用")
                applied = lab.rust(device, "wire_reclaim", receipt=confirmed["receipt"])
                report.update(event="LOST_APPLY_RETURN_MATERIAL", duplicate=applied["duplicate"],
                              reclaimed_count=applied["reclaimed_count"])
                exit_code = 92
        else:
            check(mode in ("finish", "finish_lost") and recovered["status"] == "applied",
                  "完成恢复未取得已应用计划")
            before_retry = snapshot(lab, device)
            duplicate = lab.rust(device, "wire_reclaim", receipt=recovered["finish_request"]["receipt"])
            check(duplicate["duplicate"] and duplicate["finish_request"] == recovered["finish_request"]
                  and snapshot(lab, device) == before_retry, "应用重试重新清理或改写快照")
            report.update(recovered=recovered, duplicate=True)
            try:
                report["finished"] = lab.http(device, "finish_reclaim", recovered["finish_request"])
                check(mode != "finish_lost", "预设完成中断未触发")
            except (http.client.RemoteDisconnected, ConnectionResetError) as error:
                check(mode == "finish_lost", "发生非预期 HTTP 中断")
                report.update(disconnect=type(error).__name__, event="LOST_FINISH_RESPONSE")
                exit_code = 93
    except BaseException as error:
        report["failure"] = repr(error)
        raise
    finally:
        report.update(snapshot_after=snapshot(lab, device), evidence=lab.case_evidence,
                      rust_process_count=lab.process_count, http_count=lab.http_count)
        print(json.dumps(report), flush=True)
    # 模拟宿主在材料返回后丢失全部进程内存；不新增宿主恢复账本。
    os._exit(exit_code)


if __name__ == "__main__":
    main()
