// Package users 定义业务身份接入契约；业务密码验证仍由接入方负责。
package users

import (
	"bytes"
	"encoding/json"
	m "rocket-im/service/internal/messaging"
	"time"
)

// Decode按操作拒绝多余、缺失及重复字段，避免不同JSON解释造成幂等歧义。
func Decode(op string, raw []byte) (Command, error) {
	var command Command
	allowed := map[string]bool{"service": true, "request_id": true, "external_user": true}
	switch op {
	case "users":
	case "devices":
		allowed["account"] = true
		allowed["device"] = true
		allowed["identity_key"] = true
	case "credentials":
		allowed["account"] = true
		allowed["device"] = true
		allowed["ttl_seconds"] = true
	case "revocations":
		allowed["account"] = true
		allowed["device"] = true
		allowed["credential_id"] = true
	default:
		return command, m.Fail("invalid_request")
	}
	if m.Decode(raw, &command) != nil {
		return command, m.Fail("invalid_request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	_, e := d.Token()
	if e != nil {
		return command, m.Fail("invalid_request")
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return command, m.Fail("invalid_request")
		}
		name, ok := key.(string)
		if !ok || !allowed[name] || seen[name] {
			return command, m.Fail("invalid_request")
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return command, m.Fail("invalid_request")
		}
	}
	if len(seen) != len(allowed) {
		return command, m.Fail("invalid_request")
	}
	return command, nil
}

// Command 是内部规范化命令；HTTP仍使用分操作的字段集合。
type Command struct {
	Service      string `json:"service"`
	RequestID    string `json:"request_id"`
	ExternalUser string `json:"external_user"`
	Account      string `json:"account,omitempty"`
	Device       string `json:"device,omitempty"`
	IdentityKey  string `json:"identity_key,omitempty"`
	TTLSeconds   int    `json:"ttl_seconds,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
}
type Result struct {
	ExternalUser string      `json:"external_user"`
	Account      string      `json:"account"`
	Identity     *m.Identity `json:"identity,omitempty"`
	Conversation string      `json:"conversation,omitempty"`
	Creator      bool        `json:"creator"`
	CredentialID string      `json:"credential_id,omitempty"`
	ExpiresAt    *time.Time  `json:"expires_at,omitempty"`
	Revoked      bool        `json:"revoked"`
	Token        string      `json:"token,omitempty"`
}

func (c Command) Validate(op, service string) error {
	if c.Service != service {
		return m.Fail("scope_mismatch")
	}
	if !m.ID(c.RequestID) || !m.ID(c.ExternalUser) {
		return m.Fail("invalid_request")
	}
	switch op {
	case "users":
		if c.Account != "" || c.Device != "" || c.IdentityKey != "" || c.TTLSeconds != 0 || c.CredentialID != "" {
			return m.Fail("invalid_request")
		}
	case "devices", "credentials", "revocations":
		if !m.ID(c.Account) || !m.ID(c.Device) {
			return m.Fail("invalid_request")
		}
		if op == "devices" {
			if !m.Hex(c.IdentityKey, 32, 32) || c.TTLSeconds != 0 || c.CredentialID != "" {
				return m.Fail("invalid_request")
			}
		}
		if op == "credentials" {
			if c.IdentityKey != "" || c.TTLSeconds < 1 || c.TTLSeconds > 3600 || c.CredentialID != "" {
				return m.Fail("invalid_request")
			}
		}
		if op == "revocations" {
			if c.IdentityKey != "" || c.TTLSeconds != 0 || !m.Hex(c.CredentialID, 16, 16) {
				return m.Fail("invalid_request")
			}
		}
	default:
		return m.Fail("unsupported_operation")
	}
	return nil
}
