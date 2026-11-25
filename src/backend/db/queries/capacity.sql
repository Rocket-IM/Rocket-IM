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
