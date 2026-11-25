// Package auth 管理用途隔离的访问凭证；不涉及E2EE私钥或成员密码撤销。
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Token 在重试时从秘密配置和持久ID重建；数据库不保存可直接使用的令牌。
func Token(key, service, id string) string {
	b, _ := hex.DecodeString(key)
	h := hmac.New(sha256.New, b)
	h.Write([]byte("rocket-im/device/v1\x00" + service + "\x00" + id))
	return "rimd_" + id + "_" + hex.EncodeToString(h.Sum(nil))
}
func Verify(key, service, token string) (string, bool) {
	parts := strings.Split(token, "_")
	if len(parts) != 3 || parts[0] != "rimd" || len(parts[1]) != 32 || len(parts[2]) != 64 {
		return "", false
	}
	if _, e := hex.DecodeString(parts[1]); e != nil {
		return "", false
	}
	return parts[1], hmac.Equal([]byte(Token(key, service, parts[1])), []byte(token))
}
