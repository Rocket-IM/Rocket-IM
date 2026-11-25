package rocketim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

// Capacity读取显式capacity_read权限的全Service逻辑快照，无请求号、无预留、无业务写入。
// 仅表示观察时刻；调用者仍须处理实际执行的限额、身份和维护错误。
func (c *Client) Capacity(ctx context.Context) (Capacity, error) {
	var raw json.RawMessage
	if e := c.callHTTP(ctx, http.MethodGet, "capacity", nil, &raw); e != nil {
		return Capacity{}, e
	}
	var out Capacity
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || !capacityFields(raw) || !out.valid(c.service) {
		return Capacity{}, errors.New("rocket-im: invalid_response")
	}
	return out, nil
}
func decimal(v string) (uint64, bool) {
	n, e := strconv.ParseUint(v, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == v
}
func exactFields(raw json.RawMessage, fields ...string) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) != len(fields) {
		return false
	}
	for _, k := range fields {
		if _, ok := obj[k]; !ok {
			return false
		}
	}
	return true
}
func capacityFields(raw json.RawMessage) bool {
	if !exactFields(raw, "version", "owner", "observation_id", "consistency", "scope", "schema", "budgets", "cursors", "recovery", "reserve", "operations", "physical", "remote") {
		return false
	}
	var v map[string]json.RawMessage
	_ = json.Unmarshal(raw, &v)
	for _, k := range []string{"physical", "remote"} {
		var field map[string]json.RawMessage
		_ = json.Unmarshal(v[k], &field)
		if !bytes.Equal(bytes.TrimSpace(field["reserved"]), []byte("false")) || !exactFields(v[k], "state", "reserved") {
			return false
		}
	}
	if !exactFields(v["scope"], "service", "conversation", "access", "account", "device", "principal") || !exactFields(v["reserve"], "state", "protected_remaining", "ordinary_available", "resources", "work") {
		return false
	}
	var reservation map[string]json.RawMessage
	_ = json.Unmarshal(v["reserve"], &reservation)
	for key, fields := range map[string][]string{"resources": {"category", "protected_remaining", "ordinary_available"}, "work": {"kind", "count"}} {
		var list []json.RawMessage
		if json.Unmarshal(reservation[key], &list) != nil || list == nil {
			return false
		}
		for _, item := range list {
			if !exactFields(item, fields...) {
				return false
			}
		}
	}
	var budgets, operations []json.RawMessage
	if json.Unmarshal(v["budgets"], &budgets) != nil || json.Unmarshal(v["operations"], &operations) != nil {
		return false
	}
	for _, b := range budgets {
		if !exactFields(b, "category", "unit", "state", "used", "limit", "hard_remaining", "reason", "enforcement") {
			return false
		}
	}
	for _, o := range operations {
		if !exactFields(o, "operation", "state", "blockers") {
			return false
		}
	}
	return true
}
func (c Capacity) valid(service string) bool {
	if c.Version != "service-capacity-alpha2" || c.Owner != "service" || c.Consistency != "single_pg_read" || c.Scope.Service != service || c.Scope.Access != "service" || c.Scope.Account != nil || c.Scope.Device != nil || c.Scope.Principal == nil || *c.Scope.Principal == "" || c.Scope.Conversation == "" || c.Cursors != nil || (c.Schema != "4" && c.Schema != "5" && c.Schema != "6" && c.Schema != "7") {
		return false
	}
	if len(c.ObservationID) != 64 {
		return false
	}
	for _, b := range c.ObservationID {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	if (c.Reserve.State != "not_enabled" && c.Reserve.State != "bounded_ready") || c.Reserve.ProtectedRemaining != nil || c.Reserve.OrdinaryAvailable != nil || c.Physical.State != "unavailable" || c.Physical.Reserved || c.Remote.State != "unavailable" || c.Remote.Reserved {
		return false
	}
	if !c.validReserve() {
		return false
	}
	switch c.Recovery {
	case "none", "reserved", "offered", "approved", "ready", "committed", "closing", "closed", "complete":
	default:
		return false
	}
	want := map[string]string{"accepted": "items", "business_requests": "items", "recovery_rounds": "items", "recovery_json_bytes": "bytes", "latest_round_bytes": "bytes", "reconciliation_row_bytes": "bytes", "export_row_bytes": "bytes", "export_file_bytes": "bytes"}
	if len(c.Budgets) != len(want) {
		return false
	}
	for _, b := range c.Budgets {
		if b.Enforcement != "hard_limit" && b.Enforcement != "precheck" && b.Enforcement != "not_applied" {
			return false
		}
		if want[b.Category] != b.Unit {
			return false
		}
		delete(want, b.Category)
		limit, ok := decimal(b.Limit)
		if !ok {
			return false
		}
		if b.State == "unavailable" {
			if b.Category != "export_file_bytes" || b.Used != nil || b.HardRemaining != nil || b.Reason == nil || (*b.Reason != "reconciliation_size_limit" && *b.Reason != "maintenance_not_enrolled") {
				return false
			}
			continue
		}
		if b.State != "measured" || b.Used == nil || b.HardRemaining == nil || b.Reason != nil {
			return false
		}
		used, ok := decimal(*b.Used)
		if !ok {
			return false
		}
		remaining, ok := decimal(*b.HardRemaining)
		if !ok {
			return false
		}
		expected := uint64(0)
		if used < limit {
			expected = limit - used
		}
		if remaining != expected {
			return false
		}
	}
	operations := map[string]bool{"new_send": true, "retry_send": true, "export": true, "import": true, "renew_credential": true, "revoke_credential": true, "new_recovery": true}
	if len(c.Operations) != len(operations) {
		return false
	}
	for _, o := range c.Operations {
		if !operations[o.Operation] || o.Blockers == nil || len(o.Blockers) > 8 {
			return false
		}
		delete(operations, o.Operation)
		if o.State != "blocked" && o.State != "requires_input" && o.State != "not_reserved" {
			return false
		}
		seen := map[string]bool{}
		for _, code := range o.Blockers {
			if seen[code] {
				return false
			}
			seen[code] = true
			switch code {
			case "message_limit", "context_not_accepted", "maintenance_seal_required", "export_row_limit", "reconciliation_size_limit", "maintenance_not_enrolled", "export_file_limit", "request_limit", "recovery_limit":
			default:
				return false
			}
		}
		if (o.State == "blocked") != (len(o.Blockers) > 0) {
			return false
		}
	}
	return true
}

func (c Capacity) validReserve() bool {
	if c.Reserve.Resources == nil || c.Reserve.Work == nil {
		return false
	}
	if c.Reserve.State == "not_enabled" {
		return c.Schema != "6" && c.Schema != "7" && len(c.Reserve.Resources) == 0 && len(c.Reserve.Work) == 0
	}
	if (c.Schema != "6" && c.Schema != "7") || len(c.Reserve.Resources) != 1 || len(c.Reserve.Work) != 1 {
		return false
	}
	r, w := c.Reserve.Resources[0], c.Reserve.Work[0]
	reserved, ok := decimal(r.ProtectedRemaining)
	if !ok {
		return false
	}
	available, ok := decimal(r.OrdinaryAvailable)
	if !ok {
		return false
	}
	count, ok := decimal(w.Count)
	if !ok || count > 1024 || w.Kind != "known_control_report" {
		return false
	}
	for _, b := range c.Budgets {
		if b.Category == r.Category && r.Category == "reconciliation_row_bytes" {
			if b.HardRemaining == nil {
				return false
			}
			remaining, ok := decimal(*b.HardRemaining)
			return ok && reserved <= remaining && available == remaining-reserved
		}
	}
	return false
}
