-- 只登记维护记录归属；外部进度不可从本库或备份中重新生成。
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=4;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=4);
CREATE TABLE service_maintenance (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 guard_id text NOT NULL, external_path text NOT NULL
);
