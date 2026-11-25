// Package messaging 定义固定双设备 Alpha 的公开契约，不含密码库或数据库类型。
package messaging

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
)

const Version = "alpha1"
const MaxFrame = 600 * 1024

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func ID(s string) bool { return identifier.MatchString(s) }
func Hex(s string, min, max int) bool {
	if len(s) < min*2 || len(s) > max*2 || s != string(bytes.ToLower([]byte(s))) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func Number(s string) (int64, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 || strconv.FormatInt(n, 10) != s {
		return 0, Fail("invalid_cursor")
	}
	return n, nil
}
func Decode(b []byte, target any) error {
	b = bytes.TrimSpace(b)
	if len(b) < 2 || b[0] != '{' {
		return Fail("invalid_request")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return Fail("invalid_request")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Fail("invalid_request")
	}
	return nil
}

type Failure struct {
	Code string `json:"code"`
}

func (f *Failure) Error() string { return f.Code }
func Fail(code string) error     { return &Failure{code} }
func ErrorCode(e error) string {
	var f *Failure
	if errors.As(e, &f) {
		return f.Code
	}
	return "storage_unavailable"
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
type Material struct {
	Identity   Identity `json:"identity"`
	KeyPackage string   `json:"key_package"`
}
type Envelope struct {
	Service       string `json:"service"`
	Conversation  string `json:"conversation"`
	SenderAccount string `json:"sender_account"`
	SenderDevice  string `json:"sender_device"`
	MessageID     string `json:"message_id"`
	Context       string `json:"context"`
	Ciphertext    string `json:"ciphertext"`
}
type Acceptance struct {
	RequestID    string `json:"request_id"`
	MessageID    string `json:"message_id"`
	Sequence     string `json:"sequence"`
	EnvelopeHash string `json:"envelope_hash"`
}
type Event struct {
	Sequence   string     `json:"sequence"`
	Kind       string     `json:"kind"`
	Acceptance Acceptance `json:"acceptance"`
	Envelope   *Envelope  `json:"envelope,omitempty"`
}
type Page struct {
	After  string  `json:"after"`
	Upper  string  `json:"upper"`
	Next   string  `json:"next"`
	Events []Event `json:"events"`
}
type Request struct {
	ID   string          `json:"id"`
	Op   string          `json:"op"`
	Body json.RawMessage `json:"body"`
}
type Reply struct {
	ID     string   `json:"id"`
	OK     bool     `json:"ok"`
	Result any      `json:"result"`
	Error  *Failure `json:"error"`
}
type Send struct {
	RequestID string   `json:"request_id"`
	Envelope  Envelope `json:"envelope"`
}
type Poll struct {
	After string  `json:"after"`
	Upper *string `json:"upper"`
	Limit int     `json:"limit"`
}
type Processed struct {
	Sequence    string `json:"sequence"`
	Disposition string `json:"disposition,omitempty"`
}
type Welcome struct {
	Welcome string `json:"welcome"`
}
type Session struct {
	Version      string   `json:"version"`
	Service      string   `json:"service"`
	Conversation string   `json:"conversation"`
	Own          Identity `json:"own"`
	Peer         Identity `json:"peer"`
	Creator      bool     `json:"creator"`
}
