package rocketim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func worksetFixture() map[string]any {
	fields := []string{"rocket-im/capacity-workset/1", "control-workset-v1", "service", "alice", "a1", strings.Repeat("01", 32), strings.Repeat("aa", 32), "chat", "initial", "1", "512", strings.Repeat("bb", 32)}
	raw, _ := json.Marshal(fields)
	digest := sha256.Sum256(raw)
	return map[string]any{"phase": "confirmed", "workset": map[string]any{"version": fields[1], "id": hex.EncodeToString(digest[:]),
		"owner":        map[string]any{"scope": map[string]any{"service": "service", "account": "alice", "device": "a1"}, "identity_key": fields[5]},
		"sdk_instance": fields[6], "conversation": "chat", "context": "initial", "first": "1", "last": "512", "originals_hash": fields[11]}}
}
func TestCapacityWorksetsStrictReadContract(t *testing.T) {
	cases := map[string]func(map[string]any){
		"valid":           func(map[string]any) {},
		"unknown":         func(v map[string]any) { v["extra"] = true },
		"missing":         func(v map[string]any) { delete(v, "phase") },
		"sdk_phase":       func(v map[string]any) { v["phase"] = "active" },
		"unknown_workset": func(v map[string]any) { v["workset"].(map[string]any)["extra"] = true },
		"hash":            func(v map[string]any) { v["workset"].(map[string]any)["id"] = strings.Repeat("ff", 32) },
		"number":          func(v map[string]any) { v["workset"].(map[string]any)["first"] = 1 },
		"zero":            func(v map[string]any) { v["workset"].(map[string]any)["first"] = "0" },
		"out_of_range":    func(v map[string]any) { v["workset"].(map[string]any)["last"] = "513" },
		"foreign": func(v map[string]any) {
			v["workset"].(map[string]any)["owner"].(map[string]any)["scope"].(map[string]any)["service"] = "foreign"
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			value := worksetFixture()
			change(value)
			raw, _ := json.Marshal([]any{value, nil})
			c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Method != "GET" || r.URL.Path != "/v1/business/capacity-worksets" || len(body) != 0 {
					t.Error("not a bodyless public read")
				}
				w.Write(raw)
			}, 1, time.Second)
			out, e := c.CapacityWorksets(context.Background())
			if name == "valid" {
				if e != nil || len(out) != 2 || out[0].Phase != "confirmed" || out[1] != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("accepted malformed workset")
			}
		})
	}
}
