package rocketim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

// CapacityWorkset是公开固定范围与摘要，不包含消息、密码状态或凭证。
type CapacityWorkset struct {
	Version       string   `json:"version"`
	ID            string   `json:"id"`
	Owner         Identity `json:"owner"`
	SDKInstance   string   `json:"sdk_instance"`
	Conversation  string   `json:"conversation"`
	Context       string   `json:"context"`
	First         string   `json:"first"`
	Last          string   `json:"last"`
	OriginalsHash string   `json:"originals_hash"`
	Previous      string   `json:"previous,omitempty"`
}

// Phase是Service持久观察：prepared/confirmed/settled，不等价于SDK当前已观察的阶段。
type CapacityWorksetState struct {
	Workset CapacityWorkset `json:"workset"`
	Phase   string          `json:"phase"`
}

var worksetID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var worksetDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CapacityWorksets读取capacity_read权限下固定双设备的持久工作集；nil项表示该设备未准备。
// 只读取一次Service事务，不创建/确认/解除任何承诺，也不推断SDK已收到回复。
func (c *Client) CapacityWorksets(ctx context.Context) ([]*CapacityWorksetState, error) {
	var raw json.RawMessage
	if e := c.callHTTP(ctx, http.MethodGet, "capacity-worksets", nil, &raw); e != nil {
		return nil, e
	}
	var items []json.RawMessage
	bad := errors.New("rocket-im: invalid_response")
	if json.Unmarshal(raw, &items) != nil || len(items) != 2 {
		return nil, bad
	}
	out := make([]*CapacityWorksetState, len(items))
	seen := map[Scope]bool{}
	for i, item := range items {
		if bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
			continue
		}
		var v CapacityWorksetState
		decoder := json.NewDecoder(bytes.NewReader(item))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&v) != nil || !worksetFields(item) || !v.valid(c.service) || seen[v.Workset.Owner.Scope] {
			return nil, bad
		}
		seen[v.Workset.Owner.Scope] = true
		out[i] = &v
	}
	return out, nil
}
func worksetFields(raw json.RawMessage) bool {
	if !exactFields(raw, "phase", "workset") {
		return false
	}
	var s map[string]json.RawMessage
	_ = json.Unmarshal(raw, &s)
	var w map[string]json.RawMessage
	_ = json.Unmarshal(s["workset"], &w)
	fields := []string{"version", "id", "owner", "sdk_instance", "conversation", "context", "first", "last", "originals_hash"}
	if bytes.Equal(w["version"], []byte(`"control-workset-v2"`)) {
		fields = append(fields, "previous")
	}
	if !exactFields(s["workset"], fields...) {
		return false
	}
	if !exactFields(w["owner"], "scope", "identity_key") {
		return false
	}
	var o map[string]json.RawMessage
	_ = json.Unmarshal(w["owner"], &o)
	return exactFields(o["scope"], "service", "account", "device")
}
func (s CapacityWorksetState) valid(service string) bool {
	w := s.Workset
	first, ok := decimal(w.First)
	last, ok2 := decimal(w.Last)
	versionValid := (w.Version == "control-workset-v1" && w.Previous == "") || (w.Version == "control-workset-v2" && worksetDigest.MatchString(w.Previous))
	if !ok || !ok2 || first < 1 || first > last || last > 512 || !versionValid ||
		(s.Phase != "prepared" && s.Phase != "confirmed" && s.Phase != "settled") ||
		w.Owner.Scope.Service != service || !worksetID.MatchString(w.Owner.Scope.Service) ||
		!worksetID.MatchString(w.Owner.Scope.Account) || !worksetID.MatchString(w.Owner.Scope.Device) ||
		!worksetID.MatchString(w.Conversation) || !worksetDigest.MatchString(w.Owner.IdentityKey) ||
		!worksetDigest.MatchString(w.SDKInstance) || !worksetDigest.MatchString(w.OriginalsHash) ||
		(w.Context != "initial" && !worksetDigest.MatchString(w.Context)) {
		return false
	}
	fields := []string{"rocket-im/capacity-workset/1", w.Version, w.Owner.Scope.Service, w.Owner.Scope.Account,
		w.Owner.Scope.Device, w.Owner.IdentityKey, w.SDKInstance, w.Conversation, w.Context, w.First, w.Last, w.OriginalsHash}
	if w.Version == "control-workset-v2" {
		fields[0] = "rocket-im/capacity-workset/2"
		fields = append(fields, w.Previous)
	}
	raw, _ := json.Marshal(fields)
	digest := sha256.Sum256(raw)
	return w.ID == hex.EncodeToString(digest[:])
}
