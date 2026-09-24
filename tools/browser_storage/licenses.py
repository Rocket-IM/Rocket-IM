#!/usr/bin/env python3
"""离线采集浏览器存储实验的锁定依赖许可；原文与声明均不代表法律批准。"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "poc/browser-storage/Cargo.toml"
PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")
MAX_TEXT_BYTES = 2 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def package_key(package):
    return package["name"], package["version"], package.get("source")


def checked_file(archive, members, relative):
    """只读取锁定归档内的普通文件，不提取或跟随符号链接。"""
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("路径越出精确 crate 归档")
    member = members.get(path.as_posix())
    if member is None or not member.isfile() or member.size > MAX_TEXT_BYTES:
        raise ValueError("材料缺失、不是普通文件或超过大小上限")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError("无法读取归档文件")
    with stream:
        return stream.read()


def locate_package(package, registry_roots):
    for root in registry_roots:
        path = root / f"{package['name']}-{package['version']}.crate"
        if not path.is_file():
            continue
        data = path.read_bytes()
        if sha256(data) == package.get("checksum"):
            return data
    raise ValueError("未找到与锁文件 checksum 相符的本地 .crate；请先完成锁定依赖下载")


def license_paths(members, declared_file):
    paths = {
        name for name, member in members.items()
        if member.isfile() and (
            Path(name).name.upper().startswith(PREFIXES)
            or any(part.upper().startswith(PREFIXES) for part in Path(name).parts[:-1])
        )
    }
    if declared_file:
        paths.add(declared_file)
    return sorted(paths)


def collect_package(package, registry_roots, metadata, output):
    item = {
        "name": package["name"], "version": package["version"],
        "source": package.get("source"), "lock_checksum": package.get("checksum"),
        "declared_license": None, "declared_license_file": None,
        "repository": None, "files": [], "collection_issues": [],
        "fatal_collection_issues": [], "licensing_notes": [],
    }
    try:
        if not package.get("source", "").startswith("registry+") or not package.get("checksum"):
            raise ValueError("本采集入口只接受带锁定 checksum 的 registry 依赖")
        archive_bytes = locate_package(package, registry_roots)
        prefix = f"{item['name']}-{item['version']}/"
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = {}
            for member in archive.getmembers():
                if not member.name.startswith(prefix):
                    raise ValueError("crate 归档出现预期根目录之外的成员")
                relative = member.name.removeprefix(prefix)
                if relative in members:
                    raise ValueError("crate 归档包含重复文件名")
                members[relative] = member
            manifest_bytes = checked_file(archive, members, "Cargo.toml")
            declaration = tomllib.loads(manifest_bytes.decode("utf-8"))["package"]
            if (declaration["name"], declaration["version"]) != (item["name"], item["version"]):
                raise ValueError("归档 Cargo.toml 与锁文件的名称或版本不一致")
            item.update(declared_license=declaration.get("license"),
                        declared_license_file=declaration.get("license-file", declaration.get("license_file")),
                        repository=declaration.get("repository"), manifest_sha256=sha256(manifest_bytes))
            if ".cargo_vcs_info.json" in members:
                vcs_bytes = checked_file(archive, members, ".cargo_vcs_info.json")
                item["archive_vcs"] = json.loads(vcs_bytes)
                item["archive_vcs_sha256"] = sha256(vcs_bytes)
            if metadata:
                meta_file = metadata.get("license_file")
                if meta_file and Path(meta_file).is_absolute():
                    meta_file = Path(meta_file).relative_to(Path(metadata["manifest_path"]).parent).as_posix()
                if metadata.get("license") != item["declared_license"] or meta_file != item["declared_license_file"]:
                    raise ValueError("metadata 与精确缓存归档的许可声明不一致")
            if not item["declared_license"]:
                item["licensing_notes"].append("Cargo 无 SPDX 声明；需独立核对原文，不根据文件名推断授权")
            for relative in license_paths(members, item["declared_license_file"]):
                try:
                    data = checked_file(archive, members, relative)
                    if not data.strip() or b"\0" in data:
                        raise ValueError("许可材料为空或非文本")
                    bundle_path = (Path("texts") / f"{item['name']}-{item['version']}-{item['lock_checksum'][:12]}"
                                   / relative)
                    destination = output / bundle_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    item["files"].append({
                        "path": bundle_path.as_posix(), "source_path": relative,
                        "sha256": sha256(data), "bytes": len(data), "origin": "locked_local_crate_archive",
                    })
                except (OSError, ValueError) as error:
                    item["collection_issues"].append(f"{relative}: {error}")
        if not item["files"]:
            item["collection_issues"].append("精确本地 crate 未发现可采集的许可/版权原文；不以 SPDX 文字代替")
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        item["collection_issues"].append(str(error))
        item["fatal_collection_issues"].append(str(error))
    return item


def write_reports(output, report):
    (output / "dependencies.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (output / "dependencies.tsv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(("name", "version", "source", "lock_checksum", "declared_license",
                         "declared_license_file", "files", "collection_issues", "licensing_notes"))
        for item in report["packages"]:
            writer.writerow((item["name"], item["version"], item["source"], item["lock_checksum"],
                             item["declared_license"] or "", item["declared_license_file"] or "",
                             json.dumps(item["files"], ensure_ascii=False),
                             json.dumps(item["collection_issues"], ensure_ascii=False),
                             json.dumps(item["licensing_notes"], ensure_ascii=False)))
    (output / "PROJECT-LICENSE-STATUS.txt").write_text(
        "Rocket-IM Stage 0 browser storage experiment.\n"
        "Project licensing and public distribution are not approved by this report.\n"
        "Cargo declarations and exact cached archive texts are recorded separately.\n"
        "This is conservative attribution for every locked third-party dependency,\n"
        "including build, test and other-target dependencies; it is not a runtime SBOM.\n"
        "Collection success is not legal review or a grant of rights.\n",
        encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="新的输出目录；可整目录复制进 npm 包")
    parser.add_argument("--metadata", type=Path, help="可选：同一锁文件的 cargo metadata --locked JSON")
    parser.add_argument("--require-complete", action="store_true",
                        help="缺少许可原文也返回失败；默认保留缺件并标记 REVIEW_REQUIRED")
    parser.add_argument("--cargo-home", type=Path,
                        default=Path(os.environ.get("CARGO_HOME", ROOT / "dist/toolchains/rust/cargo")))
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("输出目录必须为空，避免把前次许可文件混入本次产物")
    lock_path = MANIFEST.with_name("Cargo.lock")
    manifest_bytes, lock_bytes = MANIFEST.read_bytes(), lock_path.read_bytes()
    locked = tomllib.loads(lock_bytes.decode("utf-8"))["package"]
    metadata_packages = {}
    metadata_sha256 = None
    if args.metadata:
        metadata_bytes = args.metadata.read_bytes()
        metadata_sha256 = sha256(metadata_bytes)
        metadata_packages = {package_key(p): p for p in json.loads(metadata_bytes)["packages"]}
        if set(metadata_packages) != {package_key(p) for p in locked}:
            parser.error("metadata 包集合与 Cargo.lock 不一致；需提供未裁剪的同一锁文件 metadata")
    registry = args.cargo_home / "registry/cache"
    registry_roots = sorted(path for path in registry.iterdir() if path.is_dir()) if registry.is_dir() else []
    output.mkdir(parents=True, exist_ok=True)
    third_party = [p for p in locked if p.get("source")]
    packages = [collect_package(p, registry_roots, metadata_packages.get(package_key(p)), output)
                for p in sorted(third_party, key=package_key)]
    issues = []
    local_packages = [p for p in locked if not p.get("source")]
    project = tomllib.loads(manifest_bytes.decode("utf-8"))["package"]
    if {(p["name"], p["version"]) for p in local_packages} != {(project["name"], project["version"])}:
        issues.append("发现预期实验根包之外的本地依赖，须另行确认其归属和许可")
    if lock_path.read_bytes() != lock_bytes or MANIFEST.read_bytes() != manifest_bytes:
        issues.append("采集期间清单或锁文件发生变化，当前结果不得用于包组装")
    counts = {"locked_packages": len(locked), "third_party_packages": len(packages),
              "license_files": sum(len(p["files"]) for p in packages),
              "packages_with_collection_issues": sum(bool(p["collection_issues"]) for p in packages),
              "packages_with_fatal_collection_issues": sum(bool(p["fatal_collection_issues"]) for p in packages),
              "packages_with_licensing_notes": sum(bool(p["licensing_notes"]) for p in packages)}
    report = {
        "schema_version": 1, "collected_at": datetime.now(timezone.utc).isoformat(),
        "scope": "all locked third-party packages; conservative attribution, not runtime SBOM or legal approval",
        "manifest_path": MANIFEST.relative_to(ROOT).as_posix(), "manifest_sha256": sha256(manifest_bytes),
        "lock_sha256": sha256(lock_bytes), "metadata_sha256": metadata_sha256,
        "network_access": False, "cargo_invoked": False, "project_license": "undecided",
        "license_review_status": "REVIEW_REQUIRED", "distribution_approval": "NOT_ASSESSED",
        "require_complete": args.require_complete,
        "project_packages": local_packages, "counts": counts, "collection_issues": issues,
        "packages": packages,
    }
    report["collection_complete"] = not issues and not counts["packages_with_collection_issues"]
    report["collection_fatal"] = bool(issues or counts["packages_with_fatal_collection_issues"])
    write_reports(output, report)
    print(json.dumps({"output": str(output), "collection_complete": report["collection_complete"],
                      "collection_fatal": report["collection_fatal"],
                      "license_review_status": report["license_review_status"],
                      "counts": counts}, ensure_ascii=False))
    return int(report["collection_fatal"] or (args.require_complete and not report["collection_complete"]))


if __name__ == "__main__":
    sys.exit(main())
