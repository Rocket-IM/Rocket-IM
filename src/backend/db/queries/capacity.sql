-- name: capacity_accepted
SELECT accepted FROM alpha_conversation WHERE singleton=true
-- name: capacity_backlog
SELECT COUNT(*) FILTER (WHERE event->>'kind'='message'), COUNT(*) FILTER (WHERE event->>'kind'<>'message') FROM alpha_mailbox WHERE device_index=$1 AND sequence>$2

-- name: capacity_known_controls
WITH bounds AS (
 SELECT d.device_index,d.processed,
 COALESCE((SELECT min(m.sequence)-1 FROM alpha_mailbox m WHERE m.device_index=d.device_index AND m.sequence>d.processed AND m.event->>'kind' NOT IN ('delivered','unavailable')),d.tail) finish
 FROM alpha_devices d
), growth AS (
 SELECT count(*)::bigint n,COALESCE(sum(octet_length((to_jsonb(m)||jsonb_build_object('disposition','received'))::text)-octet_length(to_jsonb(m)::text)),0)::bigint bytes
 FROM alpha_mailbox m JOIN bounds b USING(device_index) WHERE m.sequence>b.processed AND m.sequence<=b.finish
), cursors AS (
 SELECT COALESCE(sum(octet_length((to_jsonb(d)||jsonb_build_object('processed',b.finish))::text)-octet_length(to_jsonb(d)::text)),0)::bigint bytes
 FROM alpha_devices d JOIN bounds b USING(device_index)
)
SELECT growth.n,growth.bytes+cursors.bytes FROM growth,cursors;

-- name: workset_read
SELECT capacity_workset FROM alpha_devices WHERE device_index=$1
-- name: workset_write
UPDATE alpha_devices SET capacity_workset=$2 WHERE device_index=$1
-- name: workset_history_read
SELECT capacity_workset_history FROM alpha_devices WHERE device_index=$1
-- name: workset_history_append
UPDATE alpha_devices SET capacity_workset_history=capacity_workset_history||jsonb_build_array($2::jsonb) WHERE device_index=$1
-- name: workset_originals
SELECT mb.event,m.request_id,m.message_id,m.accepted,m.envelope_hash,m.envelope,COALESCE(mb.disposition,''),m.delivered,m.context_retired
FROM alpha_mailbox mb JOIN alpha_messages m ON m.sender=mb.device_index AND m.request_id=mb.event->'acceptance'->>'request_id'
WHERE mb.device_index=$1 AND mb.sequence BETWEEN $2 AND $3 ORDER BY mb.sequence
-- name: workset_complete
SELECT d.processed >= $3 AND (SELECT count(*) FROM alpha_mailbox m WHERE m.device_index=$1 AND m.sequence BETWEEN $2 AND $3 AND m.disposition='received')=$3-$2+1
FROM alpha_devices d WHERE d.device_index=$1
-- name: workset_growth
SELECT COALESCE(sum(GREATEST(0,octet_length((to_jsonb(d)||jsonb_build_object('capacity_workset',jsonb_set(capacity_workset,'{phase}','"confirmed"')))::text)-octet_length(to_jsonb(d)::text))),0)::bigint
FROM alpha_devices d WHERE capacity_workset IS NOT NULL AND capacity_workset->>'phase'<>'settled'
