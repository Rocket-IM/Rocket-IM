"""本机五端测试进程生命周期；只管理指定的测试应用与既有专用模拟器。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlencode

SWIFT_SIMULATOR = "685CFB6F-B1F0-44FB-A889-45D56C061AFC"
FLUTTER_SIMULATOR = "29663DB5-F296-4964-9D5A-8CD8107FDFD5"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_hashes(directory):
    directory = Path(directory)
    return {str(p.relative_to(directory)): digest(p) for p in directory.rglob("*") if p.is_file()}


class Runtime:
    def __init__(self, root, work, release_root=None, interop_root=None):
        self.root, self.work = Path(root), Path(work)
        self.release_root = Path(release_root) if release_root else self.root / "dist/platform-release"
        self.interop_root = Path(interop_root) if interop_root else self.root / "dist/platform-interop"
        self.log = self.work / "runtime.log"
        self.booted_here, self.ios_apps, self.android_apps = [], [], []
        self.browser, self.android_hosts = None, None
        self.metadata = {}
        self.cleanup_errors = []

    def command(self, args, *, env=None, timeout=120, check=True):
        result = subprocess.run([str(v) for v in args], cwd=self.work, env=env,
                                capture_output=True, text=True, timeout=timeout)
        with self.log.open("a") as log:
            log.write(json.dumps({"command": [str(v) for v in args], "exit_code": result.returncode}) + "\n")
            log.write(result.stdout + result.stderr)
        if check and result.returncode:
            raise RuntimeError("runtime_command_failed:" + str(args[0]) + ":" + str(args[1]))
        return result.stdout

    def ios(self, simulator, app, bundle, endpoint, url, run_id):
        available = json.loads(self.command(["xcrun", "simctl", "list", "devices", "available", "--json"]))
        found = [(runtime, device) for runtime, devices in available["devices"].items()
                 for device in devices if device["udid"] == simulator]
        if len(found) != 1 or not found[0][1].get("isAvailable"):
            raise RuntimeError("specified_simulator_unavailable")
        runtime, device = found[0]
        self.metadata[endpoint] = {"runtime": runtime, "device": device, "physical": False}
        if device["state"] == "Shutdown":
            self.command(["xcrun", "simctl", "boot", simulator])
            self.booted_here.append(simulator)
        self.command(["xcrun", "simctl", "bootstatus", simulator, "-b"], timeout=180)
        self.command(["xcrun", "simctl", "install", simulator, app])
        self.ios_apps.append((simulator, bundle))
        installed = self.command(["xcrun", "simctl", "get_app_container", simulator, bundle, "app"]).strip()
        installed_hashes = tree_hashes(installed)
        if installed_hashes != tree_hashes(app):
            raise RuntimeError("installed_ios_app_changed:" + endpoint)
        self.metadata[endpoint]["installed_app_sha256"] = installed_hashes
        env = os.environ.copy()
        for name, value in {"URL": url, "RUN_ID": run_id, "ENDPOINT_ID": endpoint}.items():
            env["SIMCTL_CHILD_ROCKET_INTEROP_" + name] = value
        launched = self.command(["xcrun", "simctl", "launch", "--terminate-running-process", simulator, bundle], env=env)
        self.metadata[endpoint]["launch"] = launched.strip()

    def android(self, kotlin, flutter, url, run_id):
        from .android_runtime import AndroidRuntimes
        self.android_hosts = AndroidRuntimes(self.root, self.work, self.command, self.release_root, self.interop_root)
        hosts = self.android_hosts.start()
        base = url.replace("127.0.0.1", "10.0.2.2")
        apps = [(kotlin["apk"], kotlin["bundle_id"], kotlin["activity"], "kotlin-android"),
                (flutter["android_apk"], flutter["android_bundle_id"], flutter["android_activity"], "flutter-android")]
        for apk, bundle, activity, endpoint in apps:
            host = hosts[endpoint]
            adb, serial = host["adb"], host["serial"]
            if host["abi"] != "arm64-v8a" or str(host["page_size"]) != "16384":
                raise RuntimeError("unexpected_android_runtime")
            self.command([adb, "-s", serial, "install", apk])
            self.android_apps.append((adb, serial, bundle, endpoint))
            installed = self.command([adb, "-s", serial, "shell", "pm", "path", bundle]).strip()
            if not installed.startswith("package:") or "\n" in installed:
                raise RuntimeError("unexpected_android_package_paths")
            pulled = self.work / (endpoint + "-installed.apk")
            self.command([adb, "-s", serial, "pull", installed.removeprefix("package:"), pulled])
            if digest(pulled) != digest(apk):
                raise RuntimeError("installed_android_apk_changed:" + endpoint)
            self.command([adb, "-s", serial, "shell", "am", "start", "-W", "-S", "-n", bundle + "/" + activity,
                          "--es", "interop_url", base, "--es", "interop_run_id", run_id,
                          "--es", "interop_endpoint_id", endpoint])
            activities = self.command([adb, "-s", serial, "shell", "dumpsys", "activity", "activities"])
            resumed = [line.strip() for line in activities.splitlines()
                       if "ResumedActivity" in line and bundle in line]
            if not resumed:
                raise RuntimeError("test_android_activity_not_foreground:" + endpoint)
            self.metadata[endpoint] = {**host, "physical": False, "installed_apk_sha256": digest(pulled),
                                      "bundle_id": bundle, "foreground_activity": resumed}

    def chrome(self, url, run_id, playwright_module):
        query = urlencode({"interop_url": url, "interop_run_id": run_id, "interop_endpoint_id": "browser"})
        env = os.environ.copy()
        env["ROCKET_PLAYWRIGHT_MODULE"] = str(playwright_module)
        with (self.work / "browser.log").open("w") as log:
            self.browser = subprocess.Popen(["node", str(self.root / "tests/interop/platform_release/browser_host.mjs"),
                                              url + "/browser/index.html?" + query],
                                             cwd=self.work, env=env, stdout=log, stderr=subprocess.STDOUT)
        self.metadata["browser"] = {"executable": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                                    "headless": True, "process": self.browser.pid}

    def close(self):
        def attempt(action):
            try:
                action()
            except Exception as error:
                self.cleanup_errors.append(type(error).__name__ + ":" + str(error)[:160])

        if self.browser and self.browser.poll() is None:
            self.browser.terminate()
            attempt(lambda: self.browser.wait(timeout=20))
            if self.browser.poll() is None:
                self.browser.kill()
                attempt(lambda: self.browser.wait(timeout=10))
        if self.browser:
            browser_log = (self.work / "browser.log").read_text()
            if "browser_page_error" in browser_log or "browser_console_error" in browser_log:
                self.cleanup_errors.append("browser_runtime_error")
            versions = [json.loads(line)["browser_version"] for line in browser_log.splitlines()
                        if line.startswith('{"browser_version":')]
            self.metadata["browser"]["version"] = versions[0] if len(versions) == 1 else "UNAVAILABLE"
        for simulator, bundle in self.ios_apps:
            attempt(lambda s=simulator, b=bundle: self.command(["xcrun", "simctl", "terminate", s, b], check=False, timeout=20))
            attempt(lambda s=simulator, b=bundle: self.command(["xcrun", "simctl", "uninstall", s, b], timeout=30))
        for simulator in self.booted_here:
            attempt(lambda s=simulator: self.command(["xcrun", "simctl", "shutdown", s], timeout=30))
        if self.android_hosts:
            def capture():
                self.metadata["android_diagnostics"] = self.android_hosts.capture_diagnostics(
                    {endpoint: bundle for _, _, bundle, endpoint in self.android_apps})
            attempt(capture)
            for adb, serial, bundle, _ in self.android_apps:
                attempt(lambda a=adb, s=serial, b=bundle: self.command([a, "-s", s, "shell", "am", "force-stop", b], timeout=20))
                attempt(lambda a=adb, s=serial, b=bundle: self.command([a, "-s", s, "uninstall", b], timeout=30))
            self.cleanup_errors.extend(self.android_hosts.close())
