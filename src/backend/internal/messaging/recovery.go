package messaging

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// RecoveryReservation 只占用一个转交槽；不代表对端批准或密码上下文成立。
type RecoveryReservation struct {
	Version      string   `json:"version"`
	ID           string   `json:"id"`
	Target       Identity `json:"target"`
	Peer         Identity `json:"peer"`
	Conversation string   `json:"conversation"`
	OldContext   string   `json:"old_context"`
	Previous     *string  `json:"previous"`
	Request      string   `json:"request"`
	RequestHash  string   `json:"request_hash"`
	Deadline     string   `json:"deadline"`
}
type RecoveryRound struct {
	Reservation RecoveryReservation `json:"reservation"`
	Context     *string             `json:"context"`
	Status      string              `json:"status"`
	Materials   map[string]string   `json:"materials"`
}
type RecoveryQuery struct {
	ID *string `json:"id"`
}
type RecoveryPublish struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Packet string `json:"packet"`
}
type RecoveryOffer struct {
	Target       Identity           `json:"target"`
	Peer         Identity           `json:"peer"`
	Conversation string             `json:"conversation"`
	OldContext   string             `json:"old_context"`
	Previous     *string            `json:"previous"`
	Request      string             `json:"request"`
	RequestHash  string             `json:"request_hash"`
	KeyPackage   string             `json:"key_package"`
	Transport    *RecoveryTransport `json:"transport,omitempty"`
}
type RecoveryTransport struct {
	Version  string `json:"version"`
	RoundID  string `json:"round_id"`
	Deadline string `json:"deadline"`
}
type RecoveryBody struct {
	Kind         string         `json:"kind"`
	Offer        *RecoveryOffer `json:"offer,omitempty"`
	Context      string         `json:"context,omitempty"`
	Welcome      string         `json:"welcome,omitempty"`
	ApprovalHash string         `json:"approval_hash,omitempty"`
	ReadyHash    string         `json:"ready_hash,omitempty"`
	ReceiptHash  string         `json:"receipt_hash,omitempty"`
}
type RecoveryFrame struct {
	Sender    Identity     `json:"sender"`
	Body      RecoveryBody `json:"body"`
	Signature string       `json:"signature"`
}

func Digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func Equal(a, b any) bool      { x, _ := json.Marshal(a); y, _ := json.Marshal(b); return bytes.Equal(x, y) }

// ParseRecovery 核验原字节、已鉴权设备与签名；端侧仍独立核验信任和密码材料。
func ParseRecovery(packet string, expected Identity) (RecoveryBody, error) {
	var f RecoveryFrame
	if !Hex(packet, 1, 262144) {
		return f.Body, Fail("invalid_recovery_material")
	}
	raw, _ := hex.DecodeString(packet)
	if Decode(raw, &f) != nil || f.Sender != expected {
		return f.Body, Fail("recovery_identity_mismatch")
	}
	canonical, _ := json.Marshal(f)
	if !bytes.Equal(canonical, raw) || !Hex(f.Signature, 64, 64) || !Hex(expected.IdentityKey, 32, 32) {
		return f.Body, Fail("invalid_recovery_material")
	}
	key, _ := hex.DecodeString(expected.IdentityKey)
	sig, _ := hex.DecodeString(f.Signature)
	input, _ := json.Marshal([]any{f.Sender, f.Body})
	if !ed25519.Verify(key, append([]byte("Rocket-IM/SDK/recovery/v1\x00"), input...), sig) {
		return f.Body, Fail("invalid_recovery_signature")
	}
	b := f.Body
	valid := false
	allowed := RecoveryBody{Kind: b.Kind}
	switch b.Kind {
	case "offer":
		allowed.Offer = b.Offer
		valid = b.Offer != nil && b.Context == "" && Hex(b.Offer.KeyPackage, 1, 262144)
	case "approval":
		allowed.Context = b.Context
		allowed.Welcome = b.Welcome
		valid = b.Offer == nil && Hex(b.Context, 32, 32) && Hex(b.Welcome, 1, 262144)
	case "ready":
		allowed.Context = b.Context
		allowed.ApprovalHash = b.ApprovalHash
		valid = b.Offer == nil && Hex(b.Context, 32, 32) && Hex(b.ApprovalHash, 32, 32)
	case "commit":
		allowed.Context = b.Context
		allowed.ReadyHash = b.ReadyHash
		valid = b.Offer == nil && Hex(b.Context, 32, 32) && Hex(b.ReadyHash, 32, 32)
	case "close":
		allowed.Context = b.Context
		valid = b.Offer == nil && Hex(b.Context, 32, 32)
	case "installed":
		allowed.Context = b.Context
		allowed.ReceiptHash = b.ReceiptHash
		valid = b.Offer == nil && Hex(b.Context, 32, 32) && Hex(b.ReceiptHash, 32, 32)
	}
	if !valid || !Equal(b, allowed) {
		return b, Fail("invalid_recovery_material")
	}
	return b, nil
}
