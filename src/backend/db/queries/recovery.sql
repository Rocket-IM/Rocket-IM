-- name: recovery_latest
SELECT record FROM alpha_recovery ORDER BY ordinal DESC LIMIT 1
-- name: recovery_find
SELECT record FROM alpha_recovery WHERE round_id=$1
-- name: recovery_count
SELECT COUNT(*), COALESCE(SUM(octet_length(record::text)),0) FROM alpha_recovery
-- name: recovery_insert
INSERT INTO alpha_recovery(ordinal,round_id,record) VALUES($1,$2,$3)
-- name: recovery_update
UPDATE alpha_recovery SET record=$2 WHERE round_id=$1
-- name: crypto_context
SELECT crypto_context FROM alpha_conversation WHERE singleton=true
-- name: activate_context
UPDATE alpha_conversation SET crypto_context=$1 WHERE singleton=true
-- name: message_retired
UPDATE alpha_messages SET context_retired=true WHERE sender=$1 AND accepted=$2 AND envelope_hash=$3 AND NOT delivered AND NOT context_retired RETURNING request_id
-- name: mailbox_disposition
SELECT disposition FROM alpha_mailbox WHERE device_index=$1 AND sequence=$2
-- name: set_disposition
UPDATE alpha_mailbox SET disposition=$3 WHERE device_index=$1 AND sequence=$2
