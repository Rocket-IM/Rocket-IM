-- 每个原设备一个不可替换的工作集，终态保留；新旧程序不得忽略这份承诺。
ALTER TABLE alpha_devices ADD COLUMN capacity_workset jsonb;
ALTER TABLE alpha_devices ADD CONSTRAINT capacity_workset_shape CHECK (
 capacity_workset IS NULL OR (
 jsonb_typeof(capacity_workset)='object' AND
 capacity_workset ?& ARRAY['phase','workset'] AND
 jsonb_typeof(capacity_workset->'phase')='string' AND
 capacity_workset->>'phase' IN ('prepared','confirmed','settled') AND
 jsonb_typeof(capacity_workset->'workset')='object' AND
 octet_length(capacity_workset::text)<=4096
 ));
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=7;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=7);
