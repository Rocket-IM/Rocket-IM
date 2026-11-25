CREATE TABLE IF NOT EXISTS schema_version (version integer PRIMARY KEY CHECK(version = 1));
CREATE TABLE IF NOT EXISTS alpha_conversation (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), binding text NOT NULL,
 accepted bigint NOT NULL DEFAULT 0 CHECK(accepted BETWEEN 0 AND 256), welcome text
);
CREATE TABLE IF NOT EXISTS alpha_devices (
 device_index smallint PRIMARY KEY CHECK(device_index IN (0,1)),
 material jsonb, tail bigint NOT NULL DEFAULT 0 CHECK(tail BETWEEN 0 AND 512),
 processed bigint NOT NULL DEFAULT 0 CHECK(processed >= 0 AND processed <= tail)
);
CREATE TABLE IF NOT EXISTS alpha_messages (
 sender smallint NOT NULL REFERENCES alpha_devices(device_index), request_id text NOT NULL,
 message_id text NOT NULL, accepted bigint NOT NULL UNIQUE CHECK(accepted > 0),
 envelope jsonb NOT NULL, envelope_hash text NOT NULL, delivered boolean NOT NULL DEFAULT false,
 PRIMARY KEY(sender, request_id), UNIQUE(sender,message_id)
);
CREATE TABLE IF NOT EXISTS alpha_mailbox (
 device_index smallint NOT NULL REFERENCES alpha_devices(device_index), sequence bigint NOT NULL CHECK(sequence > 0),
 event jsonb NOT NULL, PRIMARY KEY(device_index,sequence)
);
INSERT INTO schema_version VALUES(1) ON CONFLICT DO NOTHING;
