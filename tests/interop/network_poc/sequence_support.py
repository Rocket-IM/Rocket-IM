"""M12.c合成大序号起点与真实Node消费装置；不改变原分页/消息实现。"""

from contextlib import closing
import copy
import hashlib
import json
import sqlite3
import subprocess

from .deletion_observer import relay_records
from .fixture import ROOT, check

BASE = 9007199254740990
SEQUENCES = [str(BASE + offset) for offset in (1, 2, 3)]


def record(lab, operation, **values):
    lab.case_evidence.setdefault("trace", []).append({"operation": operation, **values})


def node(lab, operation, *, expected=0, **fields):
    request = {"operation": operation, **fields}
    result = subprocess.run([str(lab.node_binary), str(ROOT / "tests/interop/network_poc/sequence_consumer.mjs")],
                            input=json.dumps(request), text=True, capture_output=True, timeout=15)
    lab.process_count += 1
    lab.node_count += 1
    check(result.returncode == expected and not result.stderr, "Node消费者退出或stderr不符")
    reply = json.loads(result.stdout)
    check(reply["ok"] == (expected == 0), "Node结果与退出状态不符")
    return reply["result"] if expected == 0 else reply["error"]


def pull(lab, after, limit):
    result = node(lab, "pull", url=f"http://127.0.0.1:{lab.url.port}", token=lab.tokens["b1"],
                  service_id=lab.service, stream_id=lab.streams["b1"], after_seq=str(after), limit=str(limit))
    lab.http_count += 1
    page = result["page"]
    check(result["request"]["after_seq"] == str(after) and result["request"]["limit"] == str(limit)
          and result["signature_verification"] == "delegated_to_rust" and result["response_status"] == 200,
          "JS请求未保留精确游标或误称签名验收")
    check(result["sequences"] == [event["event_seq"] for event in page["events"]], "Node序号回传与原页不符")
    record(lab, "node_http_page", result=result)
    return result


def relocate(lab):
    """仅在已停止的合成Relay库中移动3个B1原槽；不生成巨量历史或放宽分配上限。"""
    lab.stop()
    before = relay_records(lab)
    expected = copy.deepcopy(before)
    moved = [row for row in expected["events"] if row["account"] == "bob" and row["device"] == "b1"]
    check([row["seq"] for row in moved] == ["1", "2", "3"]
          and all(row["type"] == "message" for row in moved), "合成起点只适用三个原始消息槽")
    for row in moved:
        row["seq"] = str(BASE + int(row["seq"]))
    for row in expected["streams"]:
        if row["account"] == "bob" and row["device"] == "b1":
            row["watermark"] = SEQUENCES[-1]
    with closing(sqlite3.connect(lab.directory / "relay.sqlite", isolation_level=None)) as db:
        db.execute("BEGIN IMMEDIATE")
        try:
            original = db.execute("SELECT seq,typeof(seq) FROM events WHERE account=? AND device=? ORDER BY seq",
                                  ("bob", "b1")).fetchall()
            check(original == [(1, "integer"), (2, "integer"), (3, "integer")], "离线起点不是预期INTEGER序号")
            changed = db.execute("UPDATE events SET seq=seq+? WHERE account=? AND device=?", (BASE, "bob", "b1"))
            check(changed.rowcount == 3, "平移影响了错误数量的槽位")
            observed = db.execute("SELECT seq,typeof(seq) FROM events WHERE account=? AND device=? ORDER BY seq",
                                  ("bob", "b1")).fetchall()
            check(observed == [(int(seq), "integer") for seq in SEQUENCES], "SQLite未精确保存三个大INTEGER")
            db.commit()
        except BaseException:
            db.rollback()
            raise
    check(relay_records(lab) == expected, "起点平移改变了原事件身份、密文或其他消息相关记录")
    lab.start()
    check(relay_records(lab) == expected, "Relay重启改变大序号或原记录")
    record(lab, "synthetic_relay_sequence_relocation", base_seq=str(BASE), before=before, after=expected,
           observed_sqlite_sequences=[str(value) for value, _ in observed], sqlite_type="integer",
           historical_prefix="NOT_EXECUTED", normal_allocator_limit="UNCHANGED_10000")
    return expected


def snapshot(lab):
    return {str(path.relative_to(lab.directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for device in ("a1", "a2", "b1", "c1") for path in sorted((lab.directory / device).iterdir()) if path.is_file()}


def unchanged(lab, before_files, before_rows):
    check(snapshot(lab) == before_files and relay_records(lab) == before_rows,
          "拒绝/只读操作改变设备文件或已提交消息记录")


def inspect(lab, downloaded, processed, count, slots):
    value = lab.rust("b1", "wire_inspect")
    sync = value["sync"]
    check(sync["download_cursor"] == str(downloaded) and sync["processed_cursor"] == str(processed)
          and sync["source_verified"] is True and sync["slot_count"] == slots
          and value["inbox_count"] == count and not sync["halted"] and sync["quarantined_count"] == 0,
          "默认Rust加载的精确游标、来源或消息数量错误")
    return value
