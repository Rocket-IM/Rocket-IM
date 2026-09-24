#!/usr/bin/env python3
"""独立安装 tgz、严格编译消费工程并运行持久 Chrome 专用配置。"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import uuid

from build import COMPILER, OUTPUT, ROOT, run, sha, sources, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--playwright", type=Path, default=Path("/Users/amant/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright"))
    parser.add_argument("--browser", type=Path, default=Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
    args = parser.parse_args()
    run_id = str(uuid.uuid4())
    output = OUTPUT / "runs" / run_id
    output.mkdir(parents=True, exist_ok=False)
    report = {"run_id": run_id, "status": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat(),
              "archive": str(args.archive.resolve()), "archive_sha256": sha(args.archive), "source_sha256_before": sources(),
              "not_tested": ["complete native and mobile MLS transaction acceptance", "physical device and Safari/Firefox", "OS power loss and disk failure", "production independent fault domain, first enrollment trust, human recovery approval and enforced client policy", "authenticated at-rest storage, browser secret storage and secure deletion", "rebuild cancellation, recursive successor chains, old history migration and production membership authorization"]}
    try:
        consumer = output / "consumer"
        shutil.copytree(ROOT / "tests/consumers/browser-storage", consumer)
        run(["npm", "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", args.archive.resolve()],
            consumer, output / "install.log")
        run(["node", COMPILER, "-p", consumer / "tsconfig.json"], consumer, output / "consumer-typescript.log")
        installed = consumer / "node_modules/@rockets-im/browser-storage-probe"
        artifact = json.loads((installed / "artifact.json").read_text())
        mismatched = [p for p, expected in artifact["files_sha256"].items() if sha(installed / p) != expected]
        if mismatched:
            raise RuntimeError("独立安装包摘要不符：" + str(mismatched))
        report.update(installed_artifact_files=len(artifact["files_sha256"]), package_build_run_id=artifact["run_id"],
                      package_sources_match=artifact["source_sha256"] == report["source_sha256_before"])
        if not report["package_sources_match"]:
            raise RuntimeError("包所对应的源码与当前验证入口不匹配，须重新构建")
        run(["node", ROOT / "tools/browser_storage/runner.mjs", consumer, output, args.playwright, args.browser],
            ROOT, output / "browser.log", timeout=600)
        browser_report = json.loads((output / "browser.json").read_text())
        report.update(browser=browser_report, status=browser_report["status"])
    except Exception as error:
        report.update(status="FAIL", error=str(error))
        browser_result = output / "browser.json"
        if browser_result.exists():
            report["browser"] = json.loads(browser_result.read_text())
    report["source_sha256_after"] = sources()
    report["sources_unchanged"] = report["source_sha256_before"] == report["source_sha256_after"]
    report["archive_unchanged"] = report["archive_sha256"] == sha(args.archive)
    if not report["sources_unchanged"] or not report["archive_unchanged"]:
        report.update(status="FAIL", error="验证期间源或包发生变化")
    write_json(output / "report.json", report)
    print(json.dumps({"status": report["status"], "run_id": run_id, "report": str(output / "report.json"),
                      "error": report.get("error"), "cases": len(report.get("browser", {}).get("cases", []))}, ensure_ascii=False))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
