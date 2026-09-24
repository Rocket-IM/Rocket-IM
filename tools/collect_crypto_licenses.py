#!/usr/bin/env python3
"""按 POC 锁文件收集实际依赖图的许可证声明；不是许可证兼容批准。"""

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = tomllib.loads((ROOT / "poc/rust-toolchain.toml").read_text())["toolchain"]["channel"]
TARGETS = {"native": "aarch64-apple-darwin", "wasm": "wasm32-unknown-unknown"}


def main():
    rows = {}
    for candidate in ("vodozemac", "openmls"):
        manifest = ROOT / "poc" / f"{candidate}-probe/Cargo.toml"
        for label, target in TARGETS.items():
            data = json.loads(subprocess.check_output([
                "cargo", f"+{TOOLCHAIN}", "metadata", "--locked", "--offline",
                "--format-version", "1", "--filter-platform", target,
                "--manifest-path", str(manifest)], cwd=ROOT / "poc", text=True))
            packages = {p["id"]: p for p in data["packages"]}
            nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
            visited = set()
            pending = [data["resolve"]["root"]]
            while pending:
                ident = pending.pop()
                if ident in visited:
                    continue
                visited.add(ident)
                pending.extend(dep["pkg"] for dep in nodes[ident]["deps"])
                package = packages[ident]
                if package["source"] is None:
                    continue
                key = (package["name"], package["version"])
                if key not in rows:
                    folder = Path(package["manifest_path"]).parent
                    files = set(folder.glob("LICENSE*")) | set(folder.glob("COPYING*"))
                    if package["license_file"]:
                        files.add(folder / package["license_file"])
                    evidence = [f"{p.name}:{hashlib.sha256(p.read_bytes()).hexdigest()}"
                                for p in sorted(files) if p.is_file()]
                    rows[key] = {"crate": key[0], "version": key[1],
                                 "license": package["license"] or "UNDECLARED",
                                 "targets": set(), "license_file_sha256": ";".join(evidence)}
                rows[key]["targets"].add(f"{candidate}:{label}")
    destination = ROOT / "poc/依赖许可证.tsv"
    with destination.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=["crate", "version", "license", "targets",
                                                   "license_file_sha256"], delimiter="\t")
        writer.writeheader()
        for key in sorted(rows):
            row = rows[key]
            row["targets"] = ";".join(sorted(row["targets"]))
            writer.writerow(row)
    missing = [key for key, row in rows.items() if row["license"] == "UNDECLARED"]
    print(f"已记录 {len(rows)} 个依赖版本；缺少许可证声明: {missing}; 输出: {destination}")
    print("仅核对包声明与附带文件摘要；不替代逐项分发义务、项目许可证兼容和法律复核。")


if __name__ == "__main__":
    main()
