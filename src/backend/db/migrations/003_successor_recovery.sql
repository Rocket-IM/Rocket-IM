-- 恢复账本独立于普通信箱；原普通事件及接受事实保持。
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=3;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=3);
ALTER TABLE alpha_conversation ADD COLUMN crypto_context text NOT NULL DEFAULT 'initial';
ALTER TABLE alpha_messages ADD COLUMN context_retired boolean NOT NULL DEFAULT false;
ALTER TABLE alpha_mailbox ADD COLUMN disposition text;
UPDATE alpha_mailbox m SET disposition='received' FROM alpha_devices d
 WHERE m.device_index=d.device_index AND m.sequence<=d.processed;
CREATE TABLE alpha_recovery (
 ordinal integer PRIMARY KEY CHECK(ordinal BETWEEN 1 AND 16),
 round_id text NOT NULL UNIQUE, record jsonb NOT NULL
);
