-- 已结清旧轮原样追加；原工作集和原件均不删除。非空不重叠区间至多512轮。
ALTER TABLE alpha_devices ADD COLUMN capacity_workset_history jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE alpha_devices ADD CONSTRAINT capacity_workset_history_shape CHECK (
 jsonb_typeof(capacity_workset_history)='array' AND
 jsonb_array_length(capacity_workset_history)<=511 AND
 (jsonb_array_length(capacity_workset_history)=0 OR capacity_workset IS NOT NULL)
);
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=8;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=8);
