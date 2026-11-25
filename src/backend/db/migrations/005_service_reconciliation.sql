-- 独立证据先于PG提交；这里的标识仅把业务事务与该证据关联，不自证防回退。
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=5;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=5);
ALTER TABLE service_maintenance ADD COLUMN run_id text NOT NULL DEFAULT '';
ALTER TABLE service_maintenance ADD COLUMN operation_id text NOT NULL DEFAULT '';
