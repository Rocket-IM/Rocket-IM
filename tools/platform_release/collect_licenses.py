#!/usr/bin/env python3
"""采集锁定依赖的许可原文；上游补件仅使用 crate 记录的精确提交。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "dist/platform-release/licenses"
PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")
MAX_TEXT_BYTES = 2 * 1024 * 1024
MPL_URL = "https://www.mozilla.org/media/MPL/2.0/index.f75d2927d3c1.txt"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def get(url, limit=MAX_TEXT_BYTES):
    # 只取公开静态文本/API；不执行下载内容，不读取认证凭证。
    for attempt in range(2):
        try:
            with urlopen(Request(url, headers={"User-Agent": "Rocket-IM-license-collector"}),
                         timeout=35) as response:
                data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("upstream response exceeds byte limit")
            return data
        except HTTPError as error:
            if attempt or error.code not in (429, 500, 502, 503, 504):
                raise
        except (URLError, TimeoutError):
            if attempt:
                raise
    raise RuntimeError("unreachable retry state")


def text_ids(data):
    """只观察原文标题/正文特征，不把观察结果改写成 Cargo 的许可声明。"""
    text = " ".join(data.decode("utf-8").lower().split())
    found = []
    if "apache license" in text and "version 2.0, january 2004" in text:
        found.append("Apache-2.0")
    if "permission is hereby granted, free of charge" in text:
        found.append("MIT")
    if ("mozilla public license" in text and "version 2.0" in text
            and "exhibit a" in text):
        found.append("MPL-2.0")
    if "gnu lesser general public license" in text and "version 2.1" in text:
        found.append("LGPL-2.1")
    return found


def save_file(target, relative, data, **provenance):
    relative = PurePosixPath(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("invalid license output path")
    if not data.strip() or b"\0" in data:
        raise ValueError("empty or binary license text")
    data.decode("utf-8")
    if data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        raise ValueError("HTML response is not a license text")
    destination = target / str(relative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return {"path": str(destination.relative_to(OUTPUT)), "sha256": digest(data),
            "observed_license_texts": text_ids(data), **provenance}


def repository_info(package, directory):
    vcs_file = directory / ".cargo_vcs_info.json"
    if not vcs_file.is_file():
        return None
    vcs = json.loads(vcs_file.read_text())
    commit = vcs.get("git", {}).get("sha1", "")
    repository = urlparse(package.get("repository") or "")
    parts = repository.path.strip("/").split("/")
    crate_path = PurePosixPath(vcs.get("path_in_vcs", ""))
    if (repository.hostname != "github.com" or len(parts) < 2
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            or crate_path.is_absolute() or ".." in crate_path.parts):
        return None
    return {"repository": "/".join(parts[:2]).removesuffix(".git"),
            "commit": commit, "crate_path": str(crate_path),
            "archive_vcs_dirty": vcs.get("git", {}).get("dirty", False)}


def tree(key):
    repository, commit = key
    url = f"https://api.github.com/repos/{repository}/git/trees/{commit}?recursive=1"
    try:
        result = json.loads(get(url, 16 * 1024 * 1024))
        if result.get("truncated"):
            raise ValueError("repository tree is truncated")
        return key, {entry["path"]: entry for entry in result["tree"]}, None
    except (OSError, ValueError, KeyError) as error:
        return key, {}, str(error)


def candidates(entries, crate_path):
    ancestors = {str(PurePosixPath(crate_path)), "."}
    ancestors.update(str(path) for path in PurePosixPath(crate_path).parents)
    selected = []
    for path, entry in entries.items():
        item = PurePosixPath(path)
        parent = str(item.parent)
        in_license_folder = (item.parent.name.upper().startswith(PREFIXES)
                             and str(item.parent.parent) in ancestors)
        if entry["type"] == "blob" and ((parent in ancestors and item.name.upper().startswith(PREFIXES))
                                         or in_license_folder):
            selected.append(path)
    return sorted(selected)


def fetch_license(job):
    repository, commit, path, entries = job
    original = path
    try:
        for _ in range(8):
            entry = entries[path]
            url = f"https://raw.githubusercontent.com/{repository}/{commit}/{quote(path)}"
            data = get(url)
            blob_sha = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if blob_sha != entry["sha"]:
                raise ValueError("download does not match exact-commit Git blob")
            if entry["mode"] != "120000":
                return (repository, commit, original), (data, url, path, blob_sha), None
            path = os.path.normpath(str(PurePosixPath(path).parent / data.decode().strip()))
            if path.startswith("../") or path.startswith("/") or path not in entries:
                raise ValueError("license symlink escapes repository or has missing target")
        raise ValueError("license symlink chain is too long")
    except (OSError, ValueError, KeyError) as error:
        return (repository, commit, original), None, str(error)


def cached_files(previous, vcs):
    files = []
    if previous.get("vcs") != vcs or previous.get("collection_issues"):
        return files
    for entry in previous.get("files", []):
        if entry.get("origin") not in ("repository_exact_commit", "standard_license_supplement"):
            continue
        path = OUTPUT / entry["path"]
        if not path.is_file() or sha(path) != entry["sha256"]:
            return []
        files.append(entry)
    return files


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="只复用已核验的许可证，不访问网络")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    OUTPUT = args.output.resolve()
    if not OUTPUT.is_relative_to((ROOT / "dist").resolve()):
        parser.error("许可证输出必须位于项目dist目录内")
    env = os.environ.copy()
    env.update(CARGO_HOME=str(ROOT / "dist/toolchains/rust/cargo"),
               RUSTUP_HOME=str(ROOT / "dist/toolchains/rust/rustup"), CARGO_NET_OFFLINE="true")
    env["PATH"] = env["CARGO_HOME"] + "/bin:" + env.get("PATH", "")
    result = subprocess.run(["cargo", "+1.98.1", "metadata", "--format-version", "1",
        "--manifest-path", str(ROOT / "src/sdk/rust/Cargo.toml"), "--locked", "--offline"],
        env=env, capture_output=True, text=True, check=True)
    data = json.loads(result.stdout)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    old_path = OUTPUT / "dependencies.json"
    old = json.loads(old_path.read_text()) if old_path.exists() else {"packages": []}
    previous = {(item["name"], item["version"]): item for item in old["packages"]}
    packages = []
    missing = []
    for package in data["packages"]:
        if package["source"] is None:
            continue
        directory = Path(package["manifest_path"]).parent
        paths = {p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(PREFIXES)}
        for folder in directory.iterdir():
            if folder.is_dir() and folder.name.upper().startswith(PREFIXES):
                paths.update(p for p in folder.rglob("*") if p.is_file())
        # r-efi 等把许可正文和版权署名放在 AUTHORS，只有确含正文才计入。
        for authors in directory.glob("AUTHORS*"):
            if authors.is_file() and text_ids(authors.read_bytes()):
                paths.add(authors)
        if package.get("license_file"):
            declared = directory / package["license_file"]
            if declared.is_file():
                paths.add(declared)
        target = OUTPUT / (package["name"] + "-" + package["version"])
        vcs = repository_info(package, directory)
        files = [save_file(target, str(path.relative_to(directory)), path.read_bytes(), origin="crate_archive",
                          source_path=str(path.relative_to(directory)),
                          source_url=f"https://static.crates.io/crates/{package['name']}/{package['name']}-{package['version']}.crate")
                 for path in sorted(paths)]
        archive_count = len(files)
        files.extend(cached_files(previous.get((package["name"], package["version"]), {}), vcs))
        item = {"name": package["name"], "version": package["version"],
                "declared_license": package["license"], "declared_license_file": package.get("license_file"),
                "repository": package["repository"], "vcs": vcs, "files": files,
                "archive_license_file_count": archive_count, "collection_issues": [], "licensing_notes": []}
        if not item["declared_license"]:
            item["licensing_notes"].append("Cargo SPDX declaration is absent; the declared license_file and observed original text are recorded separately")
        packages.append(item)
        if not archive_count and not files:
            missing.append(item)
    keys = {(p["vcs"]["repository"], p["vcs"]["commit"]) for p in missing if p["vcs"]}
    trees = {}
    if not args.offline:
        with ThreadPoolExecutor(max_workers=6) as pool:
            trees = {key: (entries, error) for key, entries, error in pool.map(tree, sorted(keys))}
    jobs = {}
    selected = {}
    for item in missing:
        vcs = item["vcs"]
        if not vcs:
            item["collection_issues"].append("No supported repository plus exact archive VCS commit")
            continue
        entries, error = trees.get((vcs["repository"], vcs["commit"]), ({}, "Upstream lookup unavailable offline"))
        if error:
            item["collection_issues"].append(error)
            continue
        paths = candidates(entries, vcs["crate_path"])
        if not paths:
            item["collection_issues"].append("No license or notice file found in exact-commit crate ancestors")
        selected[(item["name"], item["version"])] = paths
        for path in paths:
            jobs[(vcs["repository"], vcs["commit"], path)] = (vcs["repository"], vcs["commit"], path, entries)
    with ThreadPoolExecutor(max_workers=8) as pool:
        fetched = {key: (value, error) for key, value, error in pool.map(fetch_license, jobs.values())}
    for item in missing:
        vcs = item["vcs"]
        for path in selected.get((item["name"], item["version"]), []):
            value, error = fetched[(vcs["repository"], vcs["commit"], path)]
            if error:
                item["collection_issues"].append(f"{path}: {error}")
                continue
            content, url, resolved, blob_sha = value
            item["files"].append(save_file(OUTPUT / f"{item['name']}-{item['version']}", "upstream/" + path,
                content, origin="repository_exact_commit", source_url=url, source_path=resolved,
                vcs_commit=vcs["commit"], git_blob_sha1=blob_sha))
    # HPKE 的固定 MPL 声明与同提交 monorepo 根 Apache/MIT 原文不一致。
    # 补官方明确版本正文；来源独立记录，不声称这是该 crate 随包或同提交的授权文件。
    mpl = None
    for item in packages:
        observed = {label for entry in item["files"] for label in entry.get("observed_license_texts", [])}
        if item["declared_license"] == "MPL-2.0" and "MPL-2.0" not in observed:
            item["licensing_notes"].append("Exact crate archive/repository lacks MPL-2.0 body; official versioned text is supplemental, not a repository grant")
            if not args.offline:
                try:
                    if mpl is None:
                        mpl = get(MPL_URL)
                    if "MPL-2.0" not in text_ids(mpl):
                        raise ValueError("official response is not the expected MPL-2.0 body")
                    item["files"].append(save_file(OUTPUT / f"{item['name']}-{item['version']}", "MPL-2.0-SUPPLEMENT.txt", mpl,
                        origin="standard_license_supplement", source_url=MPL_URL,
                        license_version="MPL-2.0", note="Standard text only; does not replace the crate declaration or constitute an upstream grant"))
                except (OSError, ValueError) as error:
                    item["collection_issues"].append(str(error))
        elif any(entry.get("origin") == "standard_license_supplement" for entry in item["files"]):
            item["licensing_notes"].append("Exact crate archive/repository lacks MPL-2.0 body; official versioned text is supplemental, not a repository grant")
    counts = {"packages": len(packages), "license_files": sum(len(p["files"]) for p in packages),
              "packages_without_text": sum(not p["files"] for p in packages),
              "packages_without_declared_license": sum(not p["declared_license"] for p in packages),
              "packages_with_collection_issues": sum(bool(p["collection_issues"]) for p in packages),
              "packages_with_licensing_notes": sum(bool(p["licensing_notes"]) for p in packages),
              "packages_using_standard_text_supplement": sum(any(f.get("origin") == "standard_license_supplement" for f in p["files"]) for p in packages)}
    report = {"collected_at": datetime.now(timezone.utc).isoformat(),
              "scope": "workspace metadata graph, includes build/test and target-specific dependencies; conservative attribution, not runtime size or final legal review",
              "lock_sha256": sha(ROOT / "src/sdk/rust/Cargo.lock"), "counts": counts,
              "unresolved": [{"name": p["name"], "version": p["version"], "collection_issues": p["collection_issues"],
                              "licensing_notes": p["licensing_notes"]} for p in packages if p["collection_issues"] or p["licensing_notes"]],
              "packages": packages, "project_license": "undecided; no public upload authorized"}
    (OUTPUT / "dependencies.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    (OUTPUT / "PROJECT-LICENSE-STATUS.txt").write_text(
        "Rocket-IM Stage 0 local validation artifacts.\n"
        "The project license and public distribution decision are not finalized.\n"
        "This file grants no new license. Third-party license notices are included separately.\n"
        "dependencies.json distinguishes archive texts, exact-commit supplements, and standard license texts.\n"
        "Coverage is conservative attribution and is not a final legal review.\n")
    print(json.dumps(counts, ensure_ascii=False))
    for package in packages:
        if package["collection_issues"] or package["licensing_notes"]:
            print(package["name"], package["version"], "; ".join(package["collection_issues"] + package["licensing_notes"]))


if __name__ == "__main__":
    main()
