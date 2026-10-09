"""schema7→8迁移及schema8缺账本拒绝；不重造旧设备的注册成功事实。"""

from registration_test_support import RegistrationFixture, request
from storage import Store


class RegistrationMigrationTests(RegistrationFixture):
    def legacy7(self):
        with self.store.transaction() as db:
            db.execute("DROP TABLE device_registrations")
            db.execute("DELETE FROM meta WHERE key='registration_schema'")
            db.execute("UPDATE meta SET value='rim-poc-storage-7' WHERE key='schema'")

    def refuse_twice(self, expected):
        before = self.snapshot()
        for _ in range(2):
            with self.assertRaises(ValueError) as caught:
                Store(self.path, self.fixture, self.verifier)
            self.assertEqual(str(caught.exception), expected)
            self.assertEqual(self.snapshot(), before)

    def test_schema7_upgrade_keeps_legacy_key_and_original_state_without_claiming_pop(self):
        with self.store.transaction() as db:
            db.execute("INSERT INTO device_public_keys VALUES ('A','A1',?)", (request()["signature_key"],))
        self.legacy7()
        before = self.snapshot()
        self.store = Store(self.path, self.fixture, self.verifier)
        migrated = self.snapshot()
        for table in set(before) - {"__schema__", "meta"}:
            self.assertEqual(before[table], migrated[table])
        self.assertEqual(migrated["device_registrations"], ())
        self.assertIn(("schema", "rim-poc-storage-8"), migrated["meta"])
        for _ in range(2):
            Store(self.path, self.fixture, self.verifier)
            self.assertEqual(self.snapshot(), migrated)

    def test_schema8_missing_registration_marker_refuses_without_recreation(self):
        self.begin()
        with self.store.transaction() as db:
            db.execute("DELETE FROM meta WHERE key='registration_schema'")
        self.refuse_twice("注册版本标记缺失，禁止补造注册事实")

    def test_schema8_missing_registration_table_or_unique_index_refuses(self):
        for sql, message in (("DROP INDEX completed_device_registration", "注册唯一完成约束缺失"),
                             ("DROP TABLE device_registrations", "注册持久账本缺失，禁止重新生成")):
            with self.subTest(sql=sql):
                with self.store.transaction() as db:
                    db.execute(sql)
                self.refuse_twice(message)

    def test_schema8_missing_reclamation_marker_never_reinfers_high_watermark(self):
        with self.store.transaction() as db:
            db.execute("DELETE FROM meta WHERE key='reclamation_schema'")
        self.refuse_twice("回收版本标记缺失，禁止重新生成高水位")

    def test_completed_registration_missing_key_refuses_without_recreating_binding(self):
        self.complete(self.begin())
        with self.store.transaction() as db:
            db.execute("DELETE FROM device_public_keys")
        self.refuse_twice("注册完成事实与原挑战或设备公钥不一致")

    def test_bad_persistent_challenge_refuses_with_original_schema_and_data_unchanged(self):
        self.begin()
        with self.store.transaction() as db:
            db.execute("UPDATE device_registrations SET challenge_bytes='AA=='")
        self.refuse_twice("注册持久材料无效")

    def test_invalid_old_schema_rolls_back_version_and_does_not_add_registration(self):
        self.legacy7()
        with self.store.transaction() as db:
            db.execute("DELETE FROM meta WHERE key='reclamation_schema'")
        self.refuse_twice("回收版本标记缺失，禁止重新生成高水位")
