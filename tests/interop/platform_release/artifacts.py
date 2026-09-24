"""只读核对已验收SDK到独立应用的来源，并固定实际执行文件的完整摘要。"""

import hashlib
import json
from pathlib import Path
import plistlib
import tarfile
from urllib.parse import unquote, urlparse
import zipfile


class ArtifactAuditError(RuntimeError):
    pass


def require(condition, code):
    if not condition:
        raise ArtifactAuditError(code)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def tree(directory):
    """包括全部文件及链接目标；不把Debug app的启动stub当作完整执行产物。"""
    directory = Path(directory).resolve()
    require(directory.is_dir(), "artifact_directory_missing:" + str(directory))
    files, links = {}, {}
    for path in sorted(directory.rglob("*")):
        name = str(path.relative_to(directory))
        if path.is_symlink():
            require(path.resolve().is_relative_to(directory), "artifact_symlink_outside:" + name)
            links[name] = str(path.readlink())
        if path.is_file():
            files[name] = sha(path)
    require(bool(files), "artifact_directory_empty:" + str(directory))
    return {"files_sha256": files, "symlinks": links}


def zip_files(archive, prefix):
    with zipfile.ZipFile(archive) as source:
        return {name.removeprefix(prefix): sha_bytes(source.read(name))
                for name in sorted(source.namelist()) if name.startswith(prefix) and not name.endswith("/")}


def tar_files(archive, prefix=""):
    with tarfile.open(archive) as source:
        return {item.name.removeprefix("./").removeprefix(prefix): sha_bytes(source.extractfile(item).read())
                for item in source.getmembers() if item.isfile() and item.name.removeprefix("./").startswith(prefix)}


def installed_archive(directory, expected, label):
    actual = tree(directory)
    require(actual["files_sha256"] == expected, "installed_archive_mismatch:" + label)
    require(not actual["symlinks"], "unexpected_package_symlink:" + label)
    return actual


def simulator_library(xcframework):
    xcframework = Path(xcframework).resolve()
    info = plistlib.loads((xcframework / "Info.plist").read_bytes())
    candidates = [item for item in info["AvailableLibraries"] if item.get("SupportedPlatform") == "ios"
                  and item.get("SupportedPlatformVariant") == "simulator" and "arm64" in item["SupportedArchitectures"]]
    require(len(candidates) == 1, "simulator_slice_ambiguous")
    item = candidates[0]
    library = (xcframework / item["LibraryIdentifier"] / item["LibraryPath"]).resolve()
    require(library.is_relative_to(xcframework) and library.exists(), "simulator_slice_missing")
    return library


def baseline_apk(report, platform):
    record = report if platform == "kotlin" else report["android"]
    apk = Path(record["apk"])
    require(sha(apk) == record["apk_sha256"], "accepted_runtime_apk_changed:" + platform)
    return apk, record["native"]


def apk_native(apk):
    with zipfile.ZipFile(apk) as source:
        return {name: sha_bytes(source.read(name)) for name in sorted(source.namelist())
                if name.startswith("lib/") and name.endswith(".so")}


def accepted_native(current_apk, original_report, platform, libraries):
    """AGP可剥离.so；比较原验收APK的实际打包字节，而非强求等于未剥离输入库。"""
    original_apk, records = baseline_apk(original_report, platform)
    current, original = apk_native(current_apk), apk_native(original_apk)
    names = [f"lib/{abi}/{library}" for abi in ("arm64-v8a", "x86_64") for library in libraries]
    for name in names:
        require(name in current and name in original and name in records, "apk_native_missing:" + name)
        require(current[name] == original[name] == records[name]["sha256"], "apk_native_wrong_sdk:" + platform + ":" + name)
    return {"accepted_apk": str(original_apk), "accepted_apk_sha256": sha(original_apk),
            "matched_sdk_libraries": {name: current[name] for name in names}, "all_native_sha256": current}


def swift(build, archive, root):
    consumer, app = Path(build["directory"]), Path(build["app"])
    package = consumer / "Vendor/RocketIMStage0"
    inventory = installed_archive(package, zip_files(archive, "RocketIMStage0/"), "swift")
    selected = simulator_library(package / "Artifacts/RocketIMStage0FFI.xcframework")
    linked = app.parent / selected.name
    require(sha(selected) == sha(linked), "swift_linked_library_mismatch")
    project = (consumer / "Stage0Consumer.xcodeproj/project.pbxproj").read_text()
    require("Vendor/RocketIMStage0" in project and "PBXShellScriptBuildPhase" not in project,
            "swift_consumer_package_reference_changed")
    app_inventory = tree(app)
    require(app_inventory["files_sha256"] == build["app_sha256"], "swift_app_changed_since_build")
    require(sha(app / "Stage0Consumer") == build["binary_sha256"], "swift_binary_changed_since_build")
    return {"installed_package": str(package), "installed": inventory, "selected_library": str(selected),
            "linked_library": str(linked), "linked_library_sha256": sha(linked)}, {"path": str(app), **app_inventory}


def browser(build, archive, root):
    consumer = Path(build["directory"])
    package = consumer / "node_modules/@rocket-im/stage0"
    inventory = installed_archive(package, tar_files(archive, "package/"), "browser")
    compiled = tree(consumer / "dist")
    require(compiled["files_sha256"] == build["compiled_sha256"], "browser_compiled_files_changed")
    require((consumer / "index.html").read_bytes() == (root / "tests/consumers/browser/index.html").read_bytes(),
            "browser_served_entry_changed")
    files = {"index.html": sha(consumer / "index.html")}
    files.update({"dist/" + name: value for name, value in compiled["files_sha256"].items()})
    files.update({"node_modules/@rocket-im/stage0/" + name: value for name, value in inventory["files_sha256"].items()})
    return {"installed_package": str(package), "installed": inventory}, {"path": str(consumer), "files_sha256": files, "symlinks": {}}


def kotlin(build, archive, original_report, root):
    copied_aar, apk = Path(build["sdk_package"]), Path(build["apk"])
    require(sha(copied_aar) == sha(archive) == build["sdk_sha256"], "kotlin_installed_maven_mismatch")
    require(sha(apk) == build["apk_sha256"], "kotlin_apk_changed_since_build")
    jni = zip_files(copied_aar, "jni/")
    native = apk_native(apk)
    matches = {}
    for abi in ("arm64-v8a", "x86_64"):
        key = abi + "/librocket_stage0_uniffi.so"
        require(key in jni and native.get("lib/" + key) == jni[key], "kotlin_aar_to_apk_mismatch:" + abi)
        matches[key] = jni[key]
    baseline = accepted_native(apk, original_report, "kotlin", ["librocket_stage0_uniffi.so", "libjnidispatch.so"])
    return {"installed_maven_aar": str(copied_aar), "installed_maven_sha256": sha(copied_aar),
            "aar_to_apk_sha256": matches, "native": baseline}, {"path": str(apk), "sha256": sha(apk)}


def flutter(build, archive, original_report, root):
    consumer = Path(build["consumer"])
    package = (consumer.parent / "installed-package").resolve()
    require(sha(build["sdk_package"]) == sha(archive) == build["sdk_sha256"], "flutter_source_archive_mismatch")
    inventory = installed_archive(package, tar_files(archive), "flutter")
    config_path = consumer / ".dart_tool/package_config.json"
    config = json.loads(config_path.read_text())
    entries = [item for item in config["packages"] if item["name"] == "rocket_im_stage0"]
    require(len(entries) == 1, "flutter_package_resolution_ambiguous")
    uri = entries[0]["rootUri"]
    parsed = urlparse(uri)
    require(parsed.scheme in ("", "file"), "flutter_package_resolution_scheme")
    resolved = Path(unquote(parsed.path)).resolve() if parsed.scheme else (config_path.parent / unquote(uri)).resolve()
    require(resolved == package, "flutter_dart_package_resolution_mismatch")
    plugin = consumer / "ios/.symlinks/plugins/rocket_im_stage0"
    require(plugin.resolve() == package, "flutter_ios_plugin_resolution_mismatch")
    podspec = consumer / "ios/Pods/Local Podspecs/rocket_im_stage0.podspec.json"
    pod = json.loads(podspec.read_text())
    require(pod["vendored_frameworks"] == "Frameworks/RocketStage0Flutter.xcframework" and pod["static_framework"] is True,
            "flutter_ios_framework_contract_changed")
    selected = simulator_library(package / "ios/Frameworks/RocketStage0Flutter.xcframework")
    linked = consumer / "build/ios/Debug-iphonesimulator/XCFrameworkIntermediates/rocket_im_stage0" / selected.name
    require(tree(selected) == tree(linked), "flutter_ios_selected_framework_mismatch")
    apk, app = Path(build["android_apk"]), Path(build["ios_app"])
    require(sha(apk) == build["android_apk_sha256"], "flutter_apk_changed_since_build")
    require(sha(app / "Runner") == build["ios_binary_sha256"], "flutter_runner_changed_since_build")
    require((app / "Runner.debug.dylib").is_file(), "flutter_debug_application_binary_missing")
    require((app / "Frameworks/App.framework/flutter_assets/kernel_blob.bin").is_file(), "flutter_debug_dart_kernel_missing")
    baseline = accepted_native(apk, original_report, "flutter", ["librocket_stage0_flutter.so", "libflutter.so"])
    return {"installed_package": str(package), "installed": inventory, "dart_package_resolution": str(resolved),
            "ios_plugin_resolution": str(plugin.resolve()), "ios_selected_framework": str(selected),
            "ios_linked_framework": str(linked), "ios_linked_files": tree(linked), "native": baseline}, {
                "flutter-android": {"path": str(apk), "sha256": sha(apk)}, "flutter-ios": {"path": str(app), **tree(app)}}


def audit_artifacts(builds, root):
    """返回无时间字段的稳定JSON，可在构建后和清理后严格比较；不操作任何运行端。

    builds为总runner的四项构建结果。异常表示来源链断裂，不能把运行结果记为通过。
    """
    root = Path(root).resolve()
    from interop_apple_web import ACCEPTED, accepted_entries
    acceptance_path = ACCEPTED
    accepted = {item["platform"]: item for item in accepted_entries()}
    require(set(builds) == set(accepted) == {"swift", "browser", "kotlin", "flutter"}, "artifact_platform_set_mismatch")
    result = {"status": "PASS", "acceptance_sha256": sha(acceptance_path), "packages": {}, "runtime_files": {}}
    for platform in ("swift", "browser", "kotlin", "flutter"):
        entry = accepted[platform]
        archive = root / entry["artifact"]
        require(sha(archive) == entry["sha256"], "accepted_archive_changed:" + platform)
        build = builds[platform]
        if platform in ("swift", "browser"):
            require(build["archive_sha256"] == entry["sha256"], "build_archive_not_accepted:" + platform)
            provenance, runtime = (swift if platform == "swift" else browser)(build, archive, root)
            result["runtime_files"]["swift-ios" if platform == "swift" else "browser"] = runtime
        else:
            original_report = json.loads((root / entry["report"]).read_text())
            provenance, runtime = (kotlin if platform == "kotlin" else flutter)(build, archive, original_report, root)
            if platform == "flutter":
                result["runtime_files"].update(runtime)
            else:
                result["runtime_files"]["kotlin-android"] = runtime
        result["packages"][platform] = {"archive": str(archive), "archive_sha256": entry["sha256"], **provenance}
    return result
