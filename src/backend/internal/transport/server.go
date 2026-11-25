// Package transport 提供同一严格契约的HTTPS与WSS入口，不记录凭证、请求体或密文正文。
package transport

import (
	"context"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/storage"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Store    *storage.Store
	slots    chan struct{}
	mu       sync.Mutex
	sockets  map[*websocket.Conn]struct{}
	closing  bool
	requests sync.WaitGroup
}

func New(s *storage.Store) *Server {
	return &Server{Store: s, slots: make(chan struct{}, 16), sockets: map[*websocket.Conn]struct{}{}}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		http.Error(w, "service_stopping", http.StatusServiceUnavailable)
		return
	}
	s.requests.Add(1)
	s.mu.Unlock()
	defer s.requests.Done()
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil {
		http.Error(w, "tls_required", http.StatusUpgradeRequired)
		return
	}
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if s.Store.Healthy(ctx) != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.WriteHeader(204)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		if strings.HasPrefix(r.URL.Path, "/v1/business/") {
			businessError(w, m.Fail("request_limit"))
			return
		}
		http.Error(w, "connection_limit", 429)
		return
	}
	if r.URL.Path == "/v1/capacity" || r.URL.Path == "/v1/business/capacity" || r.URL.Path == "/v1/business/capacity-worksets" {
		s.capacity(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/business/") {
		s.business(w, r)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	index, deadline, authErr := s.Store.AuthenticateDevice(ctx, token)
	cancel()
	if !ok || authErr != nil {
		status := 401
		code := "unauthorized"
		if authErr != nil && (m.ErrorCode(authErr) == "storage_unavailable" || strings.HasPrefix(m.ErrorCode(authErr), "service_reconciliation_")) {
			status = 503
			code = m.ErrorCode(authErr)
		}
		http.Error(w, code, status)
		return
	}
	if r.URL.Path == "/v1/ws" && r.Method == "GET" {
		s.websocket(w, r, token, deadline)
		return
	}
	if r.URL.Path != "/v1/rpc" || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, m.MaxFrame))
	if e != nil {
		http.Error(w, "request_too_large", 413)
		return
	}
	response := s.dispatch(r.Context(), index, raw, token)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
func (s *Server) websocket(w http.ResponseWriter, r *http.Request, token string, expiry time.Time) {
	up := websocket.Upgrader{HandshakeTimeout: 3 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}
	conn, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	defer conn.Close()
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.sockets[conn] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.sockets, conn); s.mu.Unlock() }()
	conn.SetReadLimit(m.MaxFrame)
	for {
		deadline := time.Now().Add(15 * time.Second)
		if !expiry.IsZero() && expiry.Before(deadline) {
			deadline = expiry
		}
		_ = conn.SetReadDeadline(deadline)
		kind, raw, e := conn.ReadMessage()
		if e != nil || kind != websocket.TextMessage {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		index, _, err := s.Store.AuthenticateDevice(ctx, token)
		cancel()
		if err != nil {
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "unauthorized"), time.Now().Add(time.Second))
			return
		}
		response := s.dispatch(r.Context(), index, raw, token)
		_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if conn.WriteJSON(response) != nil {
			return
		}
	}
}
func (s *Server) Close() {
	s.mu.Lock()
	s.closing = true
	for c := range s.sockets {
		_ = c.Close()
	}
	s.mu.Unlock()
}

// Drain 包括已升级的WSS处理器；http.Server.Shutdown本身不等待它们。
func (s *Server) Drain(ctx context.Context) error {
	s.Close()
	done := make(chan struct{})
	go func() { s.requests.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Server) dispatch(parent context.Context, index int, raw []byte, token string) m.Reply {
	var req m.Request
	if m.Decode(raw, &req) != nil || !m.ID(req.ID) {
		return m.Reply{Error: &m.Failure{Code: "invalid_request"}}
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	result, e := s.call(ctx, index, req, token)
	reply := m.Reply{ID: req.ID, OK: e == nil, Result: result}
	if e != nil {
		reply.Result = nil
		reply.Error = &m.Failure{Code: m.ErrorCode(e)}
	}
	return reply
}
func (s *Server) call(ctx context.Context, index int, r m.Request, token string) (any, error) {
	empty := func() error { var body struct{}; return m.Decode(r.Body, &body) }
	switch r.Op {
	case "capacity_workset_query":
		if e := empty(); e != nil {
			return nil, e
		}
		return s.Store.CapacityWorkset(ctx, token, "query", nil)
	case "capacity_workset_prepare", "capacity_workset_confirm", "capacity_workset_settle":
		var b m.CapacityWorkset
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.CapacityWorkset(ctx, token, strings.TrimPrefix(r.Op, "capacity_workset_"), &b)
	case "recovery_query":
		var b m.RecoveryQuery
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.Recovery(ctx, index, b)
	case "recovery_reserve":
		var b m.RecoveryReservation
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.ReserveRecovery(ctx, index, b)
	case "recovery_publish":
		var b m.RecoveryPublish
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.PublishRecovery(ctx, index, b)
	case "session":
		if e := empty(); e != nil {
			return nil, e
		}
		return s.Store.Session(ctx, index)
	case "publish_material":
		var b m.Material
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.Material(ctx, index, &b)
	case "peer_material":
		if e := empty(); e != nil {
			return nil, e
		}
		return s.Store.Material(ctx, 1-index, nil)
	case "publish_welcome":
		var b m.Welcome
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.Welcome(ctx, index, &b)
	case "welcome":
		if e := empty(); e != nil {
			return nil, e
		}
		return s.Store.Welcome(ctx, index, nil)
	case "send":
		var b m.Send
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.Accept(ctx, index, b)
	case "poll":
		var b m.Poll
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.Page(ctx, index, b)
	case "processed":
		var b m.Processed
		if e := m.Decode(r.Body, &b); e != nil {
			return nil, e
		}
		return s.Store.Processed(ctx, index, b)
	default:
		return nil, m.Fail("unsupported_operation")
	}
}
