-- 保留001原件；所有DDL和旧身份补录与配置验证一起事务提交。
ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check;
UPDATE schema_version SET version=2;
ALTER TABLE schema_version ADD CONSTRAINT schema_version_version_check CHECK(version=2);
CREATE TABLE business_configuration (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), key_hash text NOT NULL
);
CREATE TABLE business_users (
 principal text NOT NULL, external_user text NOT NULL, account text NOT NULL UNIQUE,
 PRIMARY KEY(principal,external_user), UNIQUE(principal,external_user,account)
);
CREATE TABLE device_identities (
 device_index smallint PRIMARY KEY REFERENCES alpha_devices(device_index),
 account text NOT NULL, device text NOT NULL, identity_key text NOT NULL UNIQUE,
 principal text, external_user text,
 FOREIGN KEY(principal,external_user,account) REFERENCES business_users(principal,external_user,account),
 CHECK((principal IS NULL) = (external_user IS NULL)), UNIQUE(account,device)
);
CREATE TABLE device_credentials (
 credential_id text PRIMARY KEY, principal text NOT NULL, external_user text NOT NULL,
 account text NOT NULL, device text NOT NULL, expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 FOREIGN KEY(principal,external_user,account) REFERENCES business_users(principal,external_user,account),
 FOREIGN KEY(account,device) REFERENCES device_identities(account,device)
);
CREATE TABLE business_requests (
 principal text NOT NULL, request_id text NOT NULL, request_hash text NOT NULL,
 result jsonb NOT NULL, PRIMARY KEY(principal,request_id)
);
