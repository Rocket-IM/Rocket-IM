package rocketim

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func capacityFixture() map[string]any {
	budgets := []any{}
	for name, unit := range map[string]string{"accepted": "items", "business_requests": "items", "recovery_rounds": "items", "recovery_json_bytes": "bytes", "latest_round_bytes": "bytes", "reconciliation_row_bytes": "bytes", "export_row_bytes": "bytes", "export_file_bytes": "bytes"} {
		budgets = append(budgets, map[string]any{"category": name, "unit": unit, "enforcement": "hard_limit", "state": "measured", "used": "9007199254740993", "limit": "18446744073709551615", "hard_remaining": "18437736874454810622", "reason": nil})
	}
	operations := []any{}
	for _, name := range []string{"new_send", "retry_send", "export", "import", "renew_credential", "revoke_credential", "new_recovery"} {
		operations = append(operations, map[string]any{"operation": name, "state": "requires_input", "blockers": []string{}})
	}
	return map[string]any{"version": "service-capacity-alpha2", "owner": "service", "observation_id": strings.Repeat("a", 64), "consistency": "single_pg_read", "scope": map[string]any{"service": "service", "conversation": "chat", "access": "service", "account": nil, "device": nil, "principal": "operator"}, "schema": "5", "budgets": budgets, "cursors": nil, "recovery": "none", "reserve": map[string]any{"state": "not_enabled", "protected_remaining": nil, "ordinary_available": nil, "resources": []any{}, "work": []any{}}, "operations": operations, "physical": map[string]any{"state": "unavailable", "reserved": false}, "remote": map[string]any{"state": "unavailable", "reserved": false}}
}
func TestCapacityStrictLosslessReadOnlyContract(t *testing.T) {
	cases := map[string]func(map[string]any){
		"valid":            func(map[string]any) {},
		"unknown":          func(v map[string]any) { v["extra"] = true },
		"missing":          func(v map[string]any) { delete(v, "cursors") },
		"null_bool":        func(v map[string]any) { v["physical"].(map[string]any)["reserved"] = nil },
		"null_remote":      func(v map[string]any) { v["remote"].(map[string]any)["reserved"] = nil },
		"unknown_recovery": func(v map[string]any) { v["recovery"] = "invented" },
		"unknown_blocker": func(v map[string]any) {
			o := v["operations"].([]any)[0].(map[string]any)
			o["state"] = "blocked"
			o["blockers"] = []string{"invented"}
		},
		"duplicate_blocker": func(v map[string]any) {
			o := v["operations"].([]any)[0].(map[string]any)
			o["state"] = "blocked"
			o["blockers"] = []string{"message_limit", "message_limit"}
		},
		"overflow":     func(v map[string]any) { v["budgets"].([]any)[0].(map[string]any)["used"] = "18446744073709551616" },
		"leading_zero": func(v map[string]any) { v["budgets"].([]any)[0].(map[string]any)["used"] = "01" },
		"number":       func(v map[string]any) { v["budgets"].([]any)[0].(map[string]any)["used"] = 1 },
		"missing_null": func(v map[string]any) { delete(v["budgets"].([]any)[0].(map[string]any), "reason") },
		"scope":        func(v map[string]any) { v["scope"].(map[string]any)["service"] = "another" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			value := capacityFixture()
			change(value)
			raw, _ := json.Marshal(value)
			c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if r.Method != "GET" || r.URL.Path != "/v1/business/capacity" || len(body) != 0 {
					t.Error("not a bodyless public GET")
				}
				w.Write(raw)
			}, 1, time.Second)
			out, e := c.Capacity(context.Background())
			if name == "valid" {
				if e != nil || *out.Budgets[0].Used != "9007199254740993" {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

func TestCapacityReservedResourcesAndStrictNestedFields(t *testing.T) {
	fixture := capacityFixture()
	fixture["schema"] = "6"
	fixture["reserve"] = map[string]any{"state": "bounded_ready", "protected_remaining": nil, "ordinary_available": nil, "resources": []any{map[string]any{"category": "reconciliation_row_bytes", "protected_remaining": "0", "ordinary_available": "10"}}, "work": []any{map[string]any{"kind": "known_control_report", "count": "1"}}}
	// Match the fixture's actual hard remainder rather than duplicate the accounting algorithm.
	raw, _ := json.Marshal(fixture)
	var capacity Capacity
	_ = json.Unmarshal(raw, &capacity)
	for _, b := range capacity.Budgets {
		if b.Category == "reconciliation_row_bytes" {
			fixture["reserve"].(map[string]any)["resources"].([]any)[0].(map[string]any)["ordinary_available"] = *b.HardRemaining
		}
	}
	raw, _ = json.Marshal(fixture)
	_ = json.Unmarshal(raw, &capacity)
	if !capacityFields(raw) || !capacity.valid("service") {
		t.Fatal("valid persisted reserve rejected")
	}
	for _, key := range []string{"resources", "work"} {
		copy := map[string]any{}
		_ = json.Unmarshal(raw, &copy)
		copy["reserve"].(map[string]any)[key].([]any)[0].(map[string]any)["unexpected"] = true
		invalid, _ := json.Marshal(copy)
		if capacityFields(invalid) {
			t.Fatal("unknown nested field accepted", key)
		}
	}
}
