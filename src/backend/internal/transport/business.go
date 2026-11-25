package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/users"
	"strings"
	"time"
)

func businessError(w http.ResponseWriter, e error) {
	code := m.ErrorCode(e)
	status := 400
	switch code {
	case "unauthorized":
		status = 401
	case "forbidden", "scope_mismatch":
		status = 403
	case "device_conflict", "idempotency_conflict", "device_not_bound", "credential_expired", "credential_revoked":
		status = 409
	case "request_limit", "device_limit":
		status = 429
	case "storage_unavailable", "service_reconciliation_required", "service_reconciliation_mismatch":
		status = 503
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": m.Failure{Code: code}})
}
func (s *Server) business(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p, authenticated := s.Store.Config.AuthenticateBusiness(token, time.Now())
	if !ok || !authenticated {
		businessError(w, m.Fail("unauthorized"))
		return
	}
	op := strings.TrimPrefix(r.URL.Path, "/v1/business/")
	if r.Method != "POST" || (op != "users" && op != "devices" && op != "credentials" && op != "revocations") {
		http.NotFound(w, r)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if e != nil {
		businessError(w, m.Fail("invalid_request"))
		return
	}
	command, e := users.Decode(op, raw)
	if e != nil {
		businessError(w, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	out, e := s.Store.Business(ctx, p, op, command)
	if e != nil {
		businessError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
