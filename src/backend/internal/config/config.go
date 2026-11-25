// Package config 接受显式固定设备或业务认证配置、凭证摘要和TLS文件，无生产默认秘密。
package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	m "rocket-im/service/internal/messaging"
)

type Device struct {
	Account     string `json:"account"`
	Device      string `json:"device"`
	IdentityKey string `json:"identity_key"`
	TokenSHA256 string `json:"token_sha256"`
}
type Config struct {
	Listen        string    `json:"listen"`
	DatabaseURL   string    `json:"database_url"`
	TLSCert       string    `json:"tls_cert"`
	TLSKey        string    `json:"tls_key"`
	Service       string    `json:"service"`
	Conversation  string    `json:"conversation"`
	Devices       []Device  `json:"devices"`
	Business      *Business `json:"business,omitempty"`
	RecoveryState string    `json:"recovery_state,omitempty"`
}

func Load(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, errors.New("config_read_failed")
	}
	if len(b) > 65536 || m.Decode(b, &c) != nil {
		return c, errors.New("invalid_config")
	}
	if c.Business != nil {
		c.Business.CredentialKey = os.Getenv(c.Business.CredentialKeyEnv)
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	invalid := errors.New("invalid_config")
	if !m.ID(c.Service) || !m.ID(c.Conversation) || (len(c.Devices) != 2 && !(len(c.Devices) == 0 && c.Business != nil)) || c.DatabaseURL == "" || c.TLSCert == "" || c.TLSKey == "" {
		return invalid
	}
	if _, e := net.ResolveTCPAddr("tcp", c.Listen); e != nil || c.Listen == "" {
		return invalid
	}
	for _, d := range c.Devices {
		if !m.ID(d.Account) || !m.ID(d.Device) || !m.Hex(d.IdentityKey, 32, 32) || !m.Hex(d.TokenSHA256, 32, 32) {
			return invalid
		}
	}
	if len(c.Devices) == 2 {
		a, b := c.Devices[0], c.Devices[1]
		if (a.Account == b.Account && a.Device == b.Device) || a.IdentityKey == b.IdentityKey || a.TokenSHA256 == b.TokenSHA256 {
			return invalid
		}
	}
	return c.validateBusiness()
}
func (c Config) Identity(index int) m.Identity {
	d := c.Devices[index]
	return m.Identity{Scope: m.Scope{Service: c.Service, Account: d.Account, Device: d.Device}, IdentityKey: d.IdentityKey}
}
func (c Config) Authenticate(token string) (int, bool) {
	if c.Business != nil {
		return 0, false
	}
	if len(token) < 32 || len(token) > 256 {
		return 0, false
	}
	sum := sha256.Sum256([]byte(token))
	for i, d := range c.Devices {
		hash, _ := hex.DecodeString(d.TokenSHA256)
		if subtle.ConstantTimeCompare(sum[:], hash) == 1 {
			return i, true
		}
	}
	return 0, false
}
func (c Config) Binding() string {
	// 配置绑定不含数据库口令或TLS路径；更改固定成员/凭证不能隐式接管旧数据。
	b, _ := json.Marshal(struct {
		Service, Conversation string
		Devices               []Device
	}{c.Service, c.Conversation, c.Devices})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
