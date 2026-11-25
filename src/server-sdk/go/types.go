// Package rocketim 是独立Service公开业务API客户端，不持有设备密码私钥。
package rocketim

import "time"

const Version = "v0.1.0-alpha.3"

// UserRequest 的RequestID由业务后台持久保存。超时后必须使用相同ID和原参数重试。
// ExternalUser来自已经验证的业务登录上下文，不能取自未经授权的客户端账号字段。
type UserRequest struct {
	RequestID    string `json:"request_id"`
	ExternalUser string `json:"external_user"`
}
type DeviceRequest struct {
	UserRequest
	Account     string `json:"account"`
	Device      string `json:"device"`
	IdentityKey string `json:"identity_key"`
}
type CredentialRequest struct {
	UserRequest
	Account string `json:"account"`
	Device  string `json:"device"`
	// TTLSeconds为1到3600秒，不能超出业务凭证的到期时间。
	TTLSeconds int `json:"ttl_seconds"`
}
type RevokeRequest struct {
	UserRequest
	Account      string `json:"account"`
	Device       string `json:"device"`
	CredentialID string `json:"credential_id"`
}
type Scope struct {
	Service string `json:"service"`
	Account string `json:"account"`
	Device  string `json:"device"`
}
type Identity struct {
	Scope       Scope  `json:"scope"`
	IdentityKey string `json:"identity_key"`
}
type User struct {
	ExternalUser string `json:"external_user"`
	Account      string `json:"account"`
}

// DeviceBinding仅为目录关联。Identity和Peer仍须通过独立可信渠道核验。
type DeviceBinding struct {
	User
	Identity     Identity `json:"identity"`
	Conversation string   `json:"conversation"`
	Creator      bool     `json:"creator"`
}

// Credential.Token为秘密，仅交付对应已认证设备；禁止写日志或当业务服务端凭证使用。
// ExpiresAt是UTC时间。重新签发需要新的RequestID，旧ID永不延长有效期。
type Credential struct {
	DeviceBinding
	CredentialID string    `json:"credential_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Token        string    `json:"token"`
}
type Revocation struct {
	DeviceBinding
	CredentialID string `json:"credential_id"`
	Revoked      bool   `json:"revoked"`
}

// APIError允许errors.As取得HTTP状态和稳定错误码；不包含请求体或凭证明文。
type APIError struct {
	StatusCode int
	Code       string
}

func (e *APIError) Error() string { return "rocket-im: " + e.Code }
