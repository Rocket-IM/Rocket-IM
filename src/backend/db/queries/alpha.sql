-- name: lock
SELECT accepted FROM alpha_conversation WHERE singleton=true FOR UPDATE
-- name: message_lookup
SELECT request_id,message_id,accepted,envelope_hash FROM alpha_messages WHERE sender=$1 AND (request_id=$2 OR message_id=$3)
-- name: insert_message
INSERT INTO alpha_messages(sender,request_id,message_id,accepted,envelope,envelope_hash) VALUES($1,$2,$3,$4,$5,$6)
-- name: accept
UPDATE alpha_conversation SET accepted=$1 WHERE singleton=true
-- name: next_sequence
UPDATE alpha_devices SET tail=tail+1 WHERE device_index=$1 RETURNING tail
-- name: append
INSERT INTO alpha_mailbox(device_index,sequence,event) VALUES($1,$2,$3)
-- name: mailbox_state
SELECT tail,processed FROM alpha_devices WHERE device_index=$1
-- name: page
SELECT event FROM alpha_mailbox WHERE device_index=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4
-- name: processed
UPDATE alpha_devices SET processed=$2 WHERE device_index=$1
-- name: delivered
UPDATE alpha_messages SET delivered=true WHERE sender=$1 AND accepted=$2 AND envelope_hash=$3 AND NOT delivered RETURNING request_id
-- name: material
SELECT material FROM alpha_devices WHERE device_index=$1
-- name: put_material
UPDATE alpha_devices SET material=$2 WHERE device_index=$1
-- name: welcome
SELECT welcome FROM alpha_conversation WHERE singleton=true
-- name: put_welcome
UPDATE alpha_conversation SET welcome=$1 WHERE singleton=true
-- name: migration_lock
SELECT pg_advisory_xact_lock(1380536369)
-- name: schema_version
SELECT COUNT(*), COALESCE(MAX(version),0) FROM schema_version
-- name: insert_binding
INSERT INTO alpha_conversation(singleton,binding) VALUES(true,$1) ON CONFLICT DO NOTHING
-- name: binding
SELECT binding FROM alpha_conversation WHERE singleton=true
-- name: insert_devices
INSERT INTO alpha_devices(device_index) VALUES(0),(1) ON CONFLICT DO NOTHING
