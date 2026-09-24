"""通过 Rust 原生 CLI 验证真实文件、进程中断与重启恢复。"""

from support import Probe, require, sha


def success(response):
    require(response.get("ok") is True and response.get("error") is None,
            f"预期成功：{response}")
    return response.get("result")


def failure(response, code, sqlite_code=None, paused=None):
    error = response.get("error") or {}
    require(response.get("ok") is False and response.get("result") is None,
            "失败仍发布成功结果")
    require(error.get("code") == code, f"错误类别不符：{error}")
    if sqlite_code is not None:
        require(error.get("sqlite_code") == sqlite_code, f"SQLite 错误码不符：{error}")
    if paused is not None:
        require(error.get("paused") is paused, f"暂停状态不符：{error}")
    require(response.get("events") == [], "失败仍发布成功事件")
    require(response.get("notification") != "delivered", "失败仍投递成功通知")
    return error


def snapshot(probe):
    response = probe.request("snapshot")
    result = success(response)
    require(response.get("events") == [], "读取快照产生写入事件")
    require(response["trace"][0] == "BEGIN" and response["trace"][-1] == "COMMIT",
            "读取快照没有显式完成事务")
    return result


def subscribe(probe):
    response = probe.request("subscribe")
    result = success(response)
    require(response.get("events") == [], "订阅发布了虚构写入事件")
    return result


def put(probe, revision, value, key="message", fault="none"):
    return probe.request("put", expected_revision=str(revision), key=key, value=value, fault=fault)


def changed(probe, revision, value, key="message"):
    response = put(probe, revision, value, key)
    result = success(response)
    require(response["events"] == [{"service": result["service"], "account": result["account"],
                                    "revision": str(int(revision) + 1)}], "提交成功事件不匹配")
    require(response.get("notification") == "delivered", "提交成功没有通知")
    require(response["trace"][0] == "BEGIN" and response["trace"][-1] == "COMMIT",
            "写入成功没有显式完成事务")
    return result


class Cases:
    def __init__(self, binary, directory, commands):
        self.binary, self.directory, self.commands = binary, directory, commands

    def probe(self, name="state.db", **options):
        return Probe(self.binary, self.directory / name, self.directory, self.commands, **options)

    def normal_restart(self):
        with self.probe() as probe:
            initial = subscribe(probe)
            require(initial["revision"] == "0" and initial["records"] == [], "新库不为空")
            require(initial["schema_version"] == 2, "新库版本不符")
            require(initial["journal_mode"] == "delete" and initial["synchronous"] == 2,
                    "耐久配置不符")
            saved = changed(probe, 0, "中文🙂\u0000ordinary-value")
            require(saved["records"][0]["value"] == "中文🙂\u0000ordinary-value", "Unicode/NUL 内容损失")
            require(saved == snapshot(probe), "写入结果与读取快照不一致")
            failure(put(probe, 0, "stale"), "revision_conflict", paused=False)
            require(snapshot(probe) == saved, "旧版本覆盖了数据")
        with self.probe() as reopened:
            require(subscribe(reopened) == saved, "正常关闭后重启快照不一致")
            recovered = snapshot(reopened)
        return {"saved": saved, "reopened": recovered, "sqlite_version": saved["sqlite_version"]}

    def scope_isolation(self):
        with self.probe() as probe:
            subscribe(probe)
            saved = changed(probe, 0, "alice-original")
        for scope in ({"account": "bob"}, {"service": "other-service"}):
            with self.probe(ready=False, **scope) as rejected:
                require(rejected.startup["error"]["code"] == "scope_mismatch", "错误范围未被拒绝")
        with self.probe("bob.db", account="bob") as bob:
            subscribe(bob)
            changed(bob, 0, "bob-independent")
        with self.probe() as reopened:
            require(snapshot(reopened) == saved, "其他账号或服务污染已有数据")
        return {"scope_rejections": 2, "independent_account": "bob", "original_unchanged": True}

    def recoverable_statement_errors(self):
        with self.probe(flags=("--test-mode",)) as probe:
            subscribe(probe)
            saved = changed(probe, 0, "original")
            write_error = failure(put(probe, 1, "uncommitted", fault="sql_after_write"),
                                  "database_error", sqlite_code=1, paused=False)
            require(snapshot(probe) == saved, "写事务失败遗留部分数据")
            read_error = failure(probe.request("snapshot", fault="read_after_snapshot"),
                                 "database_error", sqlite_code=1, paused=False)
            require(snapshot(probe) == saved, "读事务失败破坏状态")
            later = changed(probe, 1, "after-errors")
        with self.probe() as reopened:
            require(snapshot(reopened) == later, "错误后正常提交未保存")
        return {"write_error": write_error, "read_error": read_error, "continued_revision": "2"}

    def refused_commit(self):
        with self.probe(flags=("--test-mode",)) as probe:
            subscribe(probe)
            saved = changed(probe, 0, "original")
            rejected = failure(put(probe, 1, "rejected", fault="refuse_commit"),
                               "commit_failed", sqlite_code=531, paused=True)
            failure(probe.request("snapshot"), "paused", paused=True)
        with self.probe() as reopened:
            require(subscribe(reopened) == saved, "提交钩子拒绝后仍保存了写入")
            changed(reopened, 1, "after-reopen")
        return {"error": rejected, "reopen_required": True, "rejected_write_absent": True}

    def interrupted(self, checkpoint):
        with self.probe(flags=("--test-mode",)) as probe:
            subscribe(probe)
            saved = changed(probe, 0, "original")
            request_id = probe.send({"op": "put", "expected_revision": "1", "key": "second",
                                     "value": "committed-window", "fault": checkpoint})
            reached = probe.checkpoint(checkpoint)
            probe.crash()
        with self.probe() as reopened:
            recovered = subscribe(reopened)
            if checkpoint == "before_commit":
                require(recovered == saved, "提交前强杀没有恢复完整旧状态")
            else:
                require(recovered["revision"] == "2", "提交后强杀丢失已提交版本")
                expected = saved["records"] + [{"key": "second", "value": "committed-window",
                                                 "updated_revision": "2"}]
                require(recovered["records"] == expected, "提交后强杀没有恢复完整新状态")
                require(recovered["service"] == saved["service"]
                        and recovered["account"] == saved["account"], "恢复时范围改变")
            require(snapshot(reopened) == recovered, "订阅恢复快照不一致")
        return {"checkpoint": reached, "unanswered_request": request_id, "kill_returncode": -9,
                "saved": saved, "recovered": recovered, "success_response_before_kill": False}

    def kill_before_commit(self):
        return self.interrupted("before_commit")

    def kill_after_commit(self):
        return self.interrupted("after_commit")

    def real_commit_busy(self):
        with self.probe() as writer:
            subscribe(writer)
            saved = changed(writer, 0, "original")
            with self.probe(flags=("--test-mode", "--hold-reader"), ready=None) as reader:
                held = reader.checkpoint("reader_held")
                rejected = failure(put(writer, 1, "blocked"), "commit_failed", sqlite_code=5, paused=True)
                failure(writer.request("snapshot"), "paused", paused=True)
                reader.crash()
        with self.probe() as reopened:
            require(subscribe(reopened) == saved, "真实 COMMIT BUSY 后遗留写入")
            changed(reopened, 1, "after-reader-release")
        return {"reader_checkpoint": held, "error": rejected,
                "reader_reaped_before_reopen": True, "rejected_write_absent": True}

    def migration_and_rollback(self):
        flags = ("--test-mode", "--seed-v1")
        with self.probe(flags=flags) as seeded:
            old = snapshot(seeded)
            require(old["schema_version"] == 1 and old["revision"] == "1", "v1 种子状态不符")
            require(old["records"] == [{"key": "seed", "value": "v1", "updated_revision": "1"}],
                    "v1 种子记录不符")
        with self.probe(flags=("--test-mode", "--fail-migration"), ready=False) as failed:
            migration_error = failed.startup["error"]
            require(migration_error["code"] == "database_error", "迁移故障未明确返回")
        with self.probe(flags=flags) as unchanged:
            require(snapshot(unchanged) == old, "迁移失败没有恢复完整旧模式和数据")
        with self.probe() as migrated:
            current = subscribe(migrated)
            require(current == {**old, "schema_version": 2}, "正常迁移丢失或篡改旧记录")
            saved = changed(migrated, 1, "after-migration")
        with self.probe() as reopened:
            require(snapshot(reopened) == saved, "迁移完成后的新写入未保存")
        return {"migration_error": migration_error, "rolled_back_schema": 1, "migrated_schema": 2,
                "old_records_preserved": True}

    def corrupt_file(self):
        database = self.directory / "state.db"
        database.write_bytes(b"ordinary-corrupt-fixture\n" * 256)
        before = sha(database)
        with self.probe(ready=False) as rejected:
            error = rejected.startup["error"]
            require(error["code"] == "database_corrupt", "损坏文件没有明确拒绝")
        require(sha(database) == before, "损坏库被静默替换")
        return {"error": error, "file_unchanged": True}

    def control_boundaries(self):
        with self.probe() as probe:
            before = subscribe(probe)
            request_id = probe.send({"op": "put", "expected_revision": "0", "key": "message",
                                     "value": "rejected-fault", "fault": "before_commit"})
            fault = probe.next_stdout()
            require(fault.get("id") == request_id, "故障门禁响应 ID 不符")
            failure(fault, "test_mode_required", paused=False)
            probe.send({"op": "snapshot", "unexpected_field": "rejected"})
            unknown = probe.next_stdout()
            failure(unknown, "invalid_request", paused=False)
            require(snapshot(probe) == before, "控制层拒绝仍改变状态")
            saved = changed(probe, 0, "\u0000" * 4096)
            require(saved["records"][0]["value"] == "\u0000" * 4096, "合法最大值往返损失")
            failure(put(probe, 1, "\u0000" * 4097), "invalid_value", paused=False)
            require(snapshot(probe) == saved, "越界值写入改变了状态")
        with self.probe(flags=("--seed-v1",), ready=False) as seed:
            require(seed.startup["error"]["code"] == "test_mode_required", "非测试模式允许种子库")
        for database in ("", ":memory:"):
            with Probe(self.binary, database, self.directory, self.commands, ready=False) as rejected:
                require(rejected.startup["error"]["code"] == "invalid_path", "接受非持久化路径")
        with self.probe() as reopened:
            require(snapshot(reopened) == saved, "合法最大值重启恢复损失")
        return {"fault_without_test_mode_rejected": True, "seed_without_test_mode_rejected": True,
                "unknown_field_rejected": True, "nonpersistent_paths_rejected": 2,
                "accepted_nul_value_bytes": 4096, "rejected_value_bytes": 4097,
                "rejected_writes_unchanged": True}


CASE_NAMES = ("normal_restart", "scope_isolation", "recoverable_statement_errors", "refused_commit",
              "kill_before_commit", "kill_after_commit", "real_commit_busy", "migration_and_rollback",
              "corrupt_file", "control_boundaries")
