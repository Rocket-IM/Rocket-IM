package messaging

import (
	"strings"
	"testing"
)

func TestWorksetCanonicalDigest(t *testing.T) {
	w := CapacityWorkset{Version: WorksetVersion, Owner: Identity{Scope: Scope{Service: "test", Account: "alice", Device: "a1"}, IdentityKey: strings.Repeat("01", 32)}, SDKInstance: strings.Repeat("aa", 32), Conversation: "chat", Context: "initial", First: "1", Last: "2", OriginalsHash: strings.Repeat("bb", 32)}
	w.ID = w.Digest()
	if w.ID != "81368f51e502e0cfde7e723c56923389136e5afba2fd06c6830acf6d1e843e49" || w.Validate() != nil {
		t.Fatal("cross-language canonical vector")
	}
	for _, field := range []string{"version", "owner", "instance", "conversation", "context", "first", "last", "originals"} {
		bad := w
		switch field {
		case "version":
			bad.Version = "other"
		case "owner":
			bad.Owner.Scope.Device = "other"
		case "instance":
			bad.SDKInstance = strings.Repeat("cc", 32)
		case "conversation":
			bad.Conversation = "other"
		case "context":
			bad.Context = strings.Repeat("dd", 32)
		case "first":
			bad.First = "01"
		case "last":
			bad.Last = "513"
		default:
			bad.OriginalsHash = strings.Repeat("ee", 32)
		}
		if bad.Validate() == nil {
			t.Fatal("unbound field", field)
		}
	}
}

func TestRepeatedWorksetCanonicalDigest(t *testing.T) {
	w := CapacityWorkset{Version: WorksetChainVersion, Owner: Identity{Scope: Scope{Service: "test", Account: "alice", Device: "a1"}, IdentityKey: strings.Repeat("01", 32)}, SDKInstance: strings.Repeat("aa", 32), Conversation: "chat", Context: "initial", First: "3", Last: "4", OriginalsHash: strings.Repeat("bb", 32), Previous: "81368f51e502e0cfde7e723c56923389136e5afba2fd06c6830acf6d1e843e49"}
	w.ID = w.Digest()
	if w.Validate() != nil || w.ID != "04ad78a7e2dc01d74ac20ecde9b482df4654f0ff63d09dba61f3910a8ed61482" {
		t.Fatal("v2 canonical mismatch")
	}
	for _, raw := range []string{`{"version":"control-workset-v1","previous":null}`, `{"version":"control-workset-v1","previous":""}`, `{"version":"control-workset-v2","previous":null}`, `{"version":"control-workset-v2"}`} {
		var value CapacityWorkset
		if Decode([]byte(raw), &value) == nil {
			t.Fatal("accepted missing/null/foreign-version predecessor")
		}
	}
}
