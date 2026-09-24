"""两端独立Android AVD及进程诊断；只管理专用名字和本实例启动的进程。"""

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time

SDK = Path.home() / "Library/Android/sdk"
IMAGE = "system-images;android-37.1;google_apis_playstore_ps16k;arm64-v8a"
IMAGE_DIRECTORY = "system-images/android-37.1/google_apis_playstore_ps16k/arm64-v8a"


def read_ini(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith(("#", ";")):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class AndroidRuntimes:
    def __init__(self, root, work, command):
        self.root, self.work, self.command = Path(root).resolve(), Path(work).resolve(), command
        self.adb, self.emulator = SDK / "platform-tools/adb", SDK / "emulator/emulator"
        self.targets, self.processes, self.locks = {}, {}, []
        self.log = self.work / "android-runtimes.jsonl"
        self.started_epoch = None
        self.closed = False

    def _record(self, event, **values):
        with self.log.open("a") as log:
            log.write(json.dumps({"time_utc": datetime.now(timezone.utc).isoformat(), "event": event, **values}) + "\n")

    def _specifications(self):
        original_home = self.root / "dist/platform-release/android-avd"
        original_name = "RocketsIM_Stage0_16k"
        original = original_home / (original_name + ".avd")
        config = read_ini(original / "config.ini")
        index = read_ini(original_home / (original_name + ".ini"))
        if (Path(index["path"]).resolve() != original or config.get("image.sysdir.1", "").rstrip("/") != IMAGE_DIRECTORY
                or config.get("abi.type") != "arm64-v8a"):
            raise RuntimeError("original_dedicated_avd_configuration_mismatch")
        image = SDK / IMAGE_DIRECTORY
        if not (image / "source.properties").is_file():
            raise RuntimeError("required_installed_16k_system_image_missing")
        properties = read_ini(image / "source.properties")
        if properties.get("SystemImage.Abi") != "arm64-v8a" or properties.get("AndroidVersion.ApiLevel") != "37.1":
            raise RuntimeError("installed_system_image_metadata_mismatch")
        new_home = self.root / "dist/platform-interop/android-avd"
        return [
            {"endpoint": "kotlin-android", "name": original_name, "port": 5580, "avd": original,
             "home": original_home, "user_home": self.root / "dist/platform-release/android-user", "create": False,
             "lock": self.root / "dist/platform-release/android-consumer.lock"},
            {"endpoint": "flutter-android", "name": "RocketsIM_Interop_Flutter_16k", "port": 5582,
             "avd": new_home / "RocketsIM_Interop_Flutter_16k.avd", "home": new_home,
             "user_home": self.root / "dist/platform-interop/android-user", "create": True,
             "device": config.get("hw.device.name", "pixel_8"), "lock": new_home / "emulator-5582.lock"},
        ]

    def _environment(self, spec):
        for key in ("home", "user_home"):
            spec[key].mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.update(ANDROID_HOME=str(SDK), ANDROID_SDK_ROOT=str(SDK), ANDROID_AVD_HOME=str(spec["home"]),
                   ANDROID_USER_HOME=str(spec["user_home"]), JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home")
        return env

    def _ensure_avd(self, spec, env):
        index = spec["home"] / (spec["name"] + ".ini")
        if not spec["avd"].exists():
            if not spec["create"] or index.exists():
                raise RuntimeError("dedicated_avd_missing_or_partial:" + spec["name"])
            manager = SDK / "cmdline-tools/latest/bin/avdmanager"
            args = [str(manager), "create", "avd", "--name", spec["name"], "--package", IMAGE,
                    "--device", spec["device"], "--path", str(spec["avd"])]
            log = self.work / "flutter-avd-create.log"
            self._record("create_avd", command=args, log=str(log))
            with log.open("w") as output:
                result = subprocess.run(args, cwd=self.work, env=env, input="no\n", text=True,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=120)
            if result.returncode:
                raise RuntimeError("dedicated_avd_create_failed")
        config = read_ini(spec["avd"] / "config.ini")
        descriptor = read_ini(index)
        if (Path(descriptor["path"]).resolve() != spec["avd"].resolve()
                or config.get("image.sysdir.1", "").rstrip("/") != IMAGE_DIRECTORY or config.get("abi.type") != "arm64-v8a"):
            raise RuntimeError("dedicated_avd_configuration_mismatch:" + spec["name"])

    def _devices(self):
        output = self.command([self.adb, "devices"], timeout=15)
        return {line.split()[0]: line.split()[1] for line in output.splitlines()
                if line.startswith("emulator-") and len(line.split()) >= 2}

    def _name(self, serial):
        return self.command([self.adb, "-s", serial, "emu", "avd", "name"], timeout=10).splitlines()

    @staticmethod
    def _free_ports(port):
        for candidate in (port, port + 1):
            with socket.socket() as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind(("127.0.0.1", candidate))
                except OSError as error:
                    raise RuntimeError("android_dedicated_port_occupied:" + str(candidate)) from error

    def _start_one(self, spec):
        env = self._environment(spec)
        self._ensure_avd(spec, env)
        serial = "emulator-" + str(spec["port"])
        existing = self._devices().get(serial)
        process = None
        if existing is not None:
            if existing != "device" or spec["name"] not in self._name(serial):
                raise RuntimeError("android_port_has_other_or_unready_avd:" + serial)
        else:
            self._free_ports(spec["port"])
            emulator_log = self.work / (spec["endpoint"] + "-emulator.log")
            args = [str(self.emulator), "-avd", spec["name"], "-port", str(spec["port"]), "-no-window", "-no-audio",
                    "-no-boot-anim", "-no-snapshot", "-gpu", "swiftshader_indirect"]
            self._record("start_avd", endpoint=spec["endpoint"], command=args, log=str(emulator_log))
            with emulator_log.open("w") as output:
                process = subprocess.Popen(args, cwd=self.work, env=env, stdout=output, stderr=subprocess.STDOUT)
            self.processes[spec["endpoint"]] = process
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise RuntimeError("dedicated_avd_exited_during_boot:" + spec["endpoint"])
            boot = self.command([self.adb, "-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=10, check=False)
            if boot.strip() == "1":
                break
            time.sleep(2)
        else:
            raise RuntimeError("dedicated_avd_boot_timeout:" + serial)
        if spec["name"] not in self._name(serial):
            raise RuntimeError("dedicated_avd_identity_changed:" + serial)
        abi = self.command([self.adb, "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], timeout=10).strip()
        pages = self.command([self.adb, "-s", serial, "shell", "getconf", "PAGE_SIZE"], timeout=10).strip()
        if abi != "arm64-v8a" or pages != "16384":
            raise RuntimeError("dedicated_avd_runtime_mismatch:" + serial)
        result = {"adb": str(self.adb), "serial": serial, "abi": abi, "page_size": pages, "owned": process is not None,
                  "avd_name": spec["name"], "avd_path": str(spec["avd"]), "emulator_pid": process.pid if process else None,
                  "system_image": IMAGE, "system_image_metadata_sha256": sha(SDK / IMAGE_DIRECTORY / "source.properties"),
                  "avd_config_sha256": sha(spec["avd"] / "config.ini")}
        self._record("avd_ready", endpoint=spec["endpoint"], **result)
        return result

    def start(self):
        """两个AVD都就绪才返回；root随后安装、启动各自App，不与引导耗时交错。"""
        if self.closed or self.targets or self.locks:
            raise RuntimeError("android_runtimes_already_started_or_closed")
        self.work.mkdir(parents=True, exist_ok=True)
        self.started_epoch = time.time()
        try:
            specifications = self._specifications()
            for spec in specifications:
                spec["lock"].parent.mkdir(parents=True, exist_ok=True)
                lock = spec["lock"].open("a")
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except Exception:
                    lock.close()
                    raise
                self.locks.append(lock)
            self.command([self.adb, "start-server"], timeout=30)
            for spec in specifications:
                self.targets[spec["endpoint"]] = self._start_one(spec)
            return dict(self.targets)
        except Exception:
            self.close()
            raise

    def _diagnostic_command(self, serial, arguments):
        # 不经通用日志器写出未过滤的系统输出；最终仅保存目标包或PID相关内容。
        args = [str(self.adb), "-s", serial, *arguments]
        result = subprocess.run(args, cwd=self.work, text=True, capture_output=True, timeout=15)
        return result.returncode, result.stdout, result.stderr[:256]

    @staticmethod
    def _process_blocks(text, bundle):
        lines, selected = text.splitlines(), []
        active = False
        for line in lines:
            if "*APP*" in line:
                active = bundle in line
            elif line and not line[0].isspace():
                active = False
            if active or bundle in line:
                selected.append(line)
        return "\n".join(selected[:500])

    def capture_diagnostics(self, bundle_by_endpoint):
        """必须在root force-stop/uninstall前调用；不唤醒、不切前台、不改系统策略。"""
        report = {}
        for endpoint, bundle in bundle_by_endpoint.items():
            if endpoint not in self.targets or not re.fullmatch(r"io\.rocketsim\.consumer\.[A-Za-z0-9_.]+\.interop\.[A-Za-z0-9_.]+", bundle):
                raise ValueError("diagnostics_requires_this_run_unique_test_bundle")
            target = self.targets[endpoint]
            record = {"serial": target["serial"], "bundle_id": bundle, "captured_at": datetime.now(timezone.utc).isoformat()}
            try:
                code, output, error = self._diagnostic_command(target["serial"], ["shell", "pidof", bundle])
                pids = output.split() if code == 0 else []
                if not all(re.fullmatch(r"[0-9]+", pid) for pid in pids):
                    raise RuntimeError("invalid_pid_diagnostic")
                record.update(pids=pids, pidof_exit=code, pidof_error=error)
                code, output, error = self._diagnostic_command(target["serial"], ["shell", "dumpsys", "activity", "processes", bundle])
                record["process_state"] = {"exit": code, "output": self._process_blocks(output, bundle), "error": error}
                code, output, error = self._diagnostic_command(target["serial"], ["shell", "dumpsys", "activity", "exit-info", bundle])
                record["exit_info"] = {"exit": code, "output": output[:65536] if bundle in output else "No target-bundle exit record", "error": error}
                code, output, error = self._diagnostic_command(target["serial"], ["logcat", "-d", "-v", "epoch", "-s",
                    "ActivityManager:I", "ActivityTaskManager:I", "CachedAppOptimizer:V", "AndroidRuntime:E", "libc:F"])
                pattern = re.compile(r"\b(?:" + "|".join(pids) + r")\b") if pids else None
                related = []
                for line in output.splitlines():
                    try:
                        recent = float(line.split()[0]) >= self.started_epoch
                    except (ValueError, IndexError):
                        recent = False
                    if recent and (bundle in line or (pattern is not None and pattern.search(line))):
                        related.append(line)
                record["system_log"] = {"exit": code, "output": "\n".join(related[-500:]), "error": error}
                # MainActivity 只输出异常类；单独按目标 PID/tag 读取，不保存正文或堆栈。
                allowed = {"SocketTimeoutException", "SocketException", "ConnectException", "EOFException",
                           "IOException", "InterruptedIOException", "ProtocolException", "UnknownHostException",
                           "JSONException", "IllegalArgumentException", "IllegalStateException", "ClassCastException",
                           "NullPointerException", "URISyntaxException", "MalformedURLException", "Failure"}
                message = re.compile(r"\s*([0-9]+\.[0-9]+)\s+([0-9]+)\s+([0-9]+)\s+E\s+"
                                     r"RocketsInterop\s*: harness_failed: ([A-Za-z][A-Za-z0-9]*)\s*")
                record["harness_log"] = []
                for pid in pids:
                    code, output, _ = self._diagnostic_command(target["serial"], ["logcat", "-d", "--pid", pid,
                        "-v", "epoch", "-s", "RocketsInterop:E"])
                    events, discarded = [], 0
                    for line in output.splitlines():
                        match = message.fullmatch(line)
                        if (match is None or match[2] != pid or float(match[1]) < self.started_epoch
                                or match[4] not in allowed):
                            discarded += 1
                            continue
                        events.append({"epoch_seconds": match[1], "pid": pid, "tid": match[3],
                                       "event": "harness_failed", "exception_type": match[4]})
                    record["harness_log"].append({"pid": pid, "exit": code, "events": events[-32:],
                        "discarded_lines": discarded, "earlier_matching_events": max(0, len(events) - 32),
                        "error": None if code == 0 else "logcat_command_failed"})
            except Exception as error:
                record["diagnostic_error"] = type(error).__name__ + ":" + str(error)[:256]
            report[endpoint] = record
        (self.work / "android-diagnostics.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return report

    def close(self):
        """只终止本实例Popen创建的进程；借用的专用AVD保持运行。"""
        errors = []
        if self.closed:
            return errors
        self.closed = True
        for endpoint, process in self.processes.items():
            if process.poll() is None:
                try:
                    process.terminate()
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                    self._record("owned_avd_stopped", endpoint=endpoint, pid=process.pid, exit_code=process.returncode)
                except Exception as error:
                    errors.append("android_avd_cleanup:" + endpoint + ":" + type(error).__name__)
        for lock in self.locks:
            lock.close()
        self.locks.clear()
        return errors
