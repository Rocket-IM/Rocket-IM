-- name: identity
SELECT account,device,identity_key FROM device_identities WHERE device_index=$1
-- name: seed_identity
INSERT INTO device_identities(device_index,account,device,identity_key) VALUES($1,$2,$3,$4) ON CONFLICT(device_index) DO NOTHING
-- name: business_key_insert
INSERT INTO business_configuration(key_hash) VALUES($1) ON CONFLICT DO NOTHING
-- name: business_key
SELECT key_hash FROM business_configuration WHERE singleton=true
-- name: business_lookup
SELECT request_hash,result FROM business_requests WHERE principal=$1 AND request_id=$2
-- name: business_count
SELECT COUNT(*) FROM business_requests
-- name: business_remember
INSERT INTO business_requests(principal,request_id,request_hash,result) VALUES($1,$2,$3,$4)
-- name: user_lookup
SELECT account FROM business_users WHERE principal=$1 AND external_user=$2
-- name: user_insert
INSERT INTO business_users(principal,external_user,account) VALUES($1,$2,$3)
-- name: identity_lookup
SELECT device_index,account,device,identity_key,COALESCE(principal,''),COALESCE(external_user,'') FROM device_identities ORDER BY device_index
-- name: identity_insert
INSERT INTO device_identities(device_index,account,device,identity_key,principal,external_user) VALUES($1,$2,$3,$4,$5,$6)
-- name: identity_adopt
UPDATE device_identities SET principal=$2,external_user=$3 WHERE device_index=$1 AND principal IS NULL
-- name: credential_insert
INSERT INTO device_credentials(credential_id,principal,external_user,account,device,expires_at) VALUES($1,$2,$3,$4,$5,$6)
-- name: credential_lookup
SELECT principal,external_user,account,device,expires_at,revoked FROM device_credentials WHERE credential_id=$1
-- name: credential_revoke
UPDATE device_credentials SET revoked=true WHERE credential_id=$1
-- name: credential_device
SELECT device_index FROM device_identities WHERE account=$1 AND device=$2 AND principal=$3 AND external_user=$4
