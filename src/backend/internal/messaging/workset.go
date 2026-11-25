package messaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const WorksetVersion = "control-workset-v1"
const WorksetChainVersion = "control-workset-v2"

// CapacityWorkset限定固定控制原件。身份和原件必须由Service重新核对，不能当作权限标签。
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
type CapacityWorksetState struct {
	Workset CapacityWorkset `json:"workset"`
	Phase   string          `json:"phase"`
}

func (w *CapacityWorkset) UnmarshalJSON(raw []byte) error {
	type fields CapacityWorkset
	var value fields
	if e := Decode(raw, &value); e != nil {
		return e
	}
	var input map[string]json.RawMessage
	if e := json.Unmarshal(raw, &input); e != nil {
		return e
	}
	previous, present := input["previous"]
	if (value.Version == WorksetVersion && present) ||
		(value.Version == WorksetChainVersion && (!present || string(previous) == "null")) {
		return Fail("workset_invalid")
	}
	*w = CapacityWorkset(value)
	return nil
}

func WorksetHash(value any) string {
	// 内部调用者仅提供规范字符串数组或已验证的Envelope，不含可失败的编码类型。
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func (w CapacityWorkset) Digest() string {
	fields := []string{"rocket-im/capacity-workset/1", w.Version,
		w.Owner.Scope.Service, w.Owner.Scope.Account, w.Owner.Scope.Device, w.Owner.IdentityKey,
		w.SDKInstance, w.Conversation, w.Context, w.First, w.Last, w.OriginalsHash}
	if w.Version == WorksetChainVersion {
		fields[0] = "rocket-im/capacity-workset/2"
		fields = append(fields, w.Previous)
	}
	return WorksetHash(fields)
}
func (w CapacityWorkset) Validate() error {
	first, e := Number(w.First)
	last, e2 := Number(w.Last)
	versionValid := (w.Version == WorksetVersion && w.Previous == "") || (w.Version == WorksetChainVersion && Hex(w.Previous, 32, 32))
	if e != nil || e2 != nil || first < 1 || first > last || last > 512 || !versionValid ||
		!ID(w.Owner.Scope.Service) || !ID(w.Owner.Scope.Account) || !ID(w.Owner.Scope.Device) ||
		!Hex(w.Owner.IdentityKey, 32, 32) || !Hex(w.SDKInstance, 32, 32) || !ID(w.Conversation) ||
		(w.Context != "initial" && !Hex(w.Context, 32, 32)) || !Hex(w.OriginalsHash, 32, 32) || w.ID != w.Digest() {
		return Fail("workset_invalid")
	}
	return nil
}

// Follows只检查已验证manifest的接续关系；结清、原件和授权仍由原事务独立验证。
func (w CapacityWorkset) Follows(previous CapacityWorkset) bool {
	first, e := Number(w.First)
	last, e2 := Number(previous.Last)
	return e == nil && e2 == nil && w.Version == WorksetChainVersion && w.Previous == previous.ID &&
		w.Owner == previous.Owner && w.SDKInstance == previous.SDKInstance && w.Conversation == previous.Conversation && first > last
}
