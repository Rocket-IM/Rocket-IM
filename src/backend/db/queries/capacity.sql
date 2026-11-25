-- name: capacity_accepted
SELECT accepted FROM alpha_conversation WHERE singleton=true
-- name: capacity_backlog
SELECT COUNT(*) FILTER (WHERE event->>'kind'='message'), COUNT(*) FILTER (WHERE event->>'kind'<>'message') FROM alpha_mailbox WHERE device_index=$1 AND sequence>$2
