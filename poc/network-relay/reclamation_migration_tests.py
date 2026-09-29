"""schema6高水位迁移与坏库拒绝；使用显式构造的旧表形状。"""

import json
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

from quota_test_support import QuotaFixture
from storage import Store


class ReclamationMigrationTests(QuotaFixture):
    def new_database(self, name):
        self.path = Path(self.directory.name) / f"{name}.sqlite3"
        self.store = Store(self.path, self.fixture)
        self.call("submit_message", self.message("M1"))
        self.call("submit_message", self.message("M2"))

    def database_state(self):
        """检查全部表、索引及值的SQLite类型，不只比较行数或Python数值相等。"""
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            catalog = tuple(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"))
            rows = {}
            for kind, name, _, _ in catalog:
                if kind != "table":
                    continue
                quoted = '"' + name.replace('"', '""') + '"'
                columns = [row[1] for row in db.execute(f"PRAGMA table_info({quoted})")]
                expressions = []
                for column in columns:
                    column = '"' + column.replace('"', '""') + '"'
                    expressions.extend((f"typeof({column})", f"quote({column})"))
                rows[name] = tuple(db.execute(f"SELECT {','.join(expressions)} FROM {quoted} ORDER BY rowid"))
            db.commit()
            return catalog, rows

    def restart(self):
        # 独立解释器复用真实Store启动/迁移；不是HTTP、崩溃或断电模拟。
        script = """
import json, sys
from pathlib import Path
from storage import Store
try:
    Store(Path(sys.argv[1]), json.load(sys.stdin))
except ValueError as error:
    print(json.dumps({"rejected": True, "message": str(error)}, ensure_ascii=False))
else:
    print(json.dumps({"rejected": False}))
"""
        result = subprocess.run([sys.executable, "-B", "-c", script, str(self.path)],
                                input=json.dumps(self.fixture), text=True, capture_output=True,
                                cwd=Path(__file__).parent, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def refuses_twice(self, message):
        before = self.database_state()
        for restart in range(2):
            with self.subTest(restart=restart + 1):
                result = self.restart()
                self.assertEqual(self.database_state(), before)
                self.assertTrue(result["rejected"], result)
                self.assertEqual(result["message"], message)

    def legacy6(self):
        with self.store.transaction() as db:
            for table in ("stream_watermarks", "reclamation_plans", "reclamation_participants", "reclamation_selection"):
                db.execute(f"DROP TABLE {table}")
            for column in ("compacted", "payload_sha256", "payload_size"):
                db.execute(f"ALTER TABLE attempts DROP COLUMN {column}")
            db.execute("ALTER TABLE events DROP COLUMN compacted")
            db.execute("DELETE FROM meta WHERE key='reclamation_schema'")
            db.execute("UPDATE meta SET value='rim-poc-storage-6' WHERE key='schema'")

    def test_contiguous_legacy_migrates_once_without_changing_original_records(self):
        self.call("submit_message", self.message("M1"))
        self.legacy6()
        before = self.snapshot()
        self.assertEqual(self.restart(), {"rejected": False})
        after = self.snapshot()
        self.assertEqual(tuple(row[:-3] for row in after["attempts"]), before["attempts"])
        self.assertEqual(tuple(row[:-1] for row in after["events"]), before["events"])
        for table in set(before) - {"__schema__", "meta", "attempts", "events"}:
            self.assertEqual(after[table], before[table])
        self.assertEqual(after["stream_watermarks"], tuple((m["account_id"], m["device_id"], int(m["device_id"] != "A1"), 0)
                         for m in self.members))
        migrated = self.database_state()
        for _ in range(2):
            self.assertEqual(self.restart(), {"rejected": False})
            self.assertEqual(self.database_state(), migrated)

    def test_gap_or_orphan_legacy_refuses_and_rolls_back_entire_schema_upgrade(self):
        for index, mutation in enumerate(("DELETE FROM events WHERE device='B1' AND seq=1",
                         "UPDATE events SET account='orphan' WHERE device='B1'",
                         "UPDATE events SET seq=0 WHERE device='B1' AND seq=1")):
            with self.subTest(mutation=mutation):
                self.new_database(f"broken-{index}")
                self.legacy6()
                with self.store.transaction() as db:
                    db.execute(mutation)
                self.refuses_twice(("旧设备流存在缺槽，拒绝推断高水位",
                                    "旧事件不属于任何已登记设备，拒绝迁移",
                                    "旧事件序号类型或范围无效，拒绝迁移")[index])

    def test_new_schema_missing_marker_or_high_watermark_never_reinfers_it(self):
        for index, mutation in enumerate(("DELETE FROM meta WHERE key='reclamation_schema'",
                                         "DELETE FROM stream_watermarks WHERE device='B1'")):
            with self.subTest(mutation=mutation):
                self.new_database(f"missing-{index}")
                with self.store.transaction() as db:
                    db.execute(mutation)
                self.refuses_twice(("回收版本标记缺失，禁止重新生成高水位",
                                    "设备流高水位账本缺失或边界无效")[index])

    def test_legacy_noninteger_sequences_refuse_without_partial_upgrade(self):
        for name, value, kind in (("text", "not-a-sequence", "text"), ("real", 1.5, "real"),
                                  ("blob", b"2", "blob"), ("null", None, "null"),
                                  ("overflow", "9223372036854775808", "real")):
            with self.subTest(value=name):
                self.new_database(f"legacy-{name}")
                self.legacy6()
                with self.store.transaction() as db:
                    db.execute("UPDATE events SET seq=? WHERE device='B1' AND seq=2", (value,))
                    self.assertEqual(db.execute("SELECT typeof(seq) FROM events WHERE device='B1' AND seq IS ?", (value,)).fetchone()[0], kind)
                self.refuses_twice("旧事件序号类型或范围无效，拒绝迁移")

    def test_numeric_values_stored_as_integers_migrate_without_false_rejection(self):
        for index, value in enumerate(("2", 2.0)):
            with self.subTest(input_type=type(value).__name__):
                self.new_database(f"integer-affinity-{index}")
                self.legacy6()
                with self.store.transaction() as db:
                    db.execute("UPDATE events SET seq=? WHERE device='B1' AND seq=2", (value,))
                    self.assertEqual(db.execute("SELECT typeof(seq) FROM events WHERE device='B1' AND seq=2").fetchone()[0], "integer")
                before = self.snapshot()
                self.assertEqual(self.restart(), {"rejected": False})
                after = self.snapshot()
                self.assertEqual(tuple(row[:-1] for row in after["events"]), before["events"])
                self.assertEqual(tuple(row[:-3] for row in after["attempts"]), before["attempts"])
                migrated = self.database_state()
                self.assertEqual(self.restart(), {"rejected": False})
                self.assertEqual(self.database_state(), migrated)

    def test_new_schema_each_missing_auxiliary_table_refuses_without_recreation(self):
        for table in ("stream_watermarks", "reclamation_plans", "reclamation_participants", "reclamation_selection"):
            with self.subTest(table=table):
                self.new_database(f"missing-{table}")
                with self.store.transaction() as db:
                    db.execute(f"DROP TABLE {table}")
                self.refuses_twice("回收持久账本缺失，禁止重新推断")

    def test_unknown_reclamation_version_refuses_without_rewrite(self):
        with self.store.transaction() as db:
            db.execute("UPDATE meta SET value='rim-reclamation-storage-999' WHERE key='reclamation_schema'")
        self.refuses_twice("不支持此回收存储版本")

    def test_invalid_watermark_bounds_or_types_refuse_without_normalization(self):
        for name, high, floor in (("negative-floor", 2, -1), ("negative-high", -1, 0),
                                  ("floor-after-high", 2, 3), ("text-high", "bad", 0),
                                  ("real-high", 2.5, 0), ("real-floor", 2, 0.5),
                                  ("blob-high", b"2", 0), ("text-both", "z", "a"),
                                  ("null-high", None, 0), ("null-floor", 2, None)):
            with self.subTest(value=name):
                self.new_database(f"watermark-{name}")
                with self.store.transaction() as db:
                    if high is None or floor is None:
                        # 正常表的NOT NULL拒绝此写入；显式弱化约束模拟旧库损坏，不声称正常API可达。
                        with self.assertRaises(sqlite3.IntegrityError):
                            db.execute("UPDATE stream_watermarks SET high_watermark=?,floor=? WHERE device='B1'", (high, floor))
                        sql = db.execute("SELECT sql FROM sqlite_master WHERE name='stream_watermarks'").fetchone()[0]
                        db.execute("ALTER TABLE stream_watermarks RENAME TO corrupt_watermarks")
                        db.execute(sql.replace(" NOT NULL", ""))
                        db.execute("INSERT INTO stream_watermarks SELECT * FROM corrupt_watermarks")
                        db.execute("DROP TABLE corrupt_watermarks")
                    db.execute("UPDATE stream_watermarks SET high_watermark=?,floor=? WHERE device='B1'", (high, floor))
                self.refuses_twice("设备流高水位账本缺失或边界无效")

    def test_high_watermark_below_saved_event_refuses_without_reinferring_it(self):
        self.new_database("regressed-high-watermark")
        with self.store.transaction() as db:
            db.execute("UPDATE stream_watermarks SET high_watermark=1 WHERE device='B1'")
            self.assertEqual(db.execute("SELECT MAX(seq) FROM events WHERE device='B1'").fetchone()[0], 2)
        self.refuses_twice("设备流高水位低于已存事件，拒绝反推修补")
