package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	m "rocket-im/service/internal/messaging"
	"strings"
	"time"
)

// Business 的签发密钥只从指定环境变量注入，不进入JSON配置或日志。
type Business struct {
	CredentialKeyEnv string      `json:"credential_key_env"`
	CredentialKey    string      `json:"-"`
	Principals       []Principal `json:"principals"`
}
type Principal struct {
	// 显式授予全局容量只读权限；省略时旧配置摘要保持不变。
	CapacityRead bool      `json:"capacity_read,omitempty"`
	ID           string    `json:"id"`
	TokenSHA256  string    `json:"token_sha256"`
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
	// 仅旧Alpha升级使用：部署方显式授权既有账号归属，禁止API自行认领。
	LegacyUsers map[string]string `json:"legacy_users,omitempty"`
}

func (c Config) validateBusiness() error {
	if c.Business == nil {
		return nil
	}
	b := c.Business
	invalid := errors.New("invalid_business_config")
	if !m.ID(b.CredentialKeyEnv) || !m.Hex(b.CredentialKey, 32, 32) || len(b.Principals) < 1 || len(b.Principals) > 8 {
		return invalid
	}
	ids, hashes, legacy := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range b.Principals {
		if !m.ID(p.ID) || !m.Hex(p.TokenSHA256, 32, 32) || ids[p.ID] || hashes[p.TokenSHA256] || p.NotBefore.IsZero() || !p.ExpiresAt.After(p.NotBefore) {
			return invalid
		}
		ids[p.ID] = true
		hashes[p.TokenSHA256] = true
		for external, account := range p.LegacyUsers {
			if !m.ID(external) || legacy[account] {
				return invalid
			}
			found := false
			for _, d := range c.Devices {
				if d.Account == account {
					found = true
				}
			}
			if !found {
				return invalid
			}
			legacy[account] = true
		}
	}
	return nil
}
func (c Config) BusinessPrincipal(id string, now time.Time) (Principal, bool) {
	if c.Business != nil {
		for _, p := range c.Business.Principals {
			if p.ID == id && !now.Before(p.NotBefore) && now.Before(p.ExpiresAt) {
				return p, true
			}
		}
	}
	return Principal{}, false
}
func (c Config) AuthenticateBusiness(token string, now time.Time) (Principal, bool) {
	if c.Business == nil || !strings.HasPrefix(token, "rimb_") || len(token) != 69 {
		return Principal{}, false
	}
	h := sha256.Sum256([]byte(token))
	for _, p := range c.Business.Principals {
		v, _ := hex.DecodeString(p.TokenSHA256)
		if subtle.ConstantTimeCompare(h[:], v) == 1 {
			return c.BusinessPrincipal(p.ID, now)
		}
	}
	return Principal{}, false
}
