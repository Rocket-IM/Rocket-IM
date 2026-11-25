-- schema6显式启用已知控制报告的有限逻辑余量；原件就是持久工作集，不复制账本。
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=6;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=6);
