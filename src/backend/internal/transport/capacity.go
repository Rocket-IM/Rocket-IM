package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	m "rocket-im/service/internal/messaging"
	"strings"
	"time"
)

func (s *Server) capacity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	// 查询无参数、无请求号、无正文；拒绝未知输入，不静默扩展范围。
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
	if e != nil || len(raw) != 0 || r.URL.RawQuery != "" {
		businessError(w, m.Fail("invalid_request"))
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		businessError(w, m.Fail("unauthorized"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var out any
	if r.URL.Path == "/v1/business/capacity-worksets" {
		out, e = s.Store.CapacityWorksets(ctx, token)
	} else if r.URL.Path == "/v1/business/capacity" {
		out, e = s.Store.CapacityBusiness(ctx, token)
	} else {
		out, e = s.Store.CapacityDevice(ctx, token)
	}
	if e != nil {
		businessError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
