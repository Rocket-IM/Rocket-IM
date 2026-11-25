// 示例把合成业务会话替换为IM访问凭证；实际业务只需替换authenticate的登录上下文来源。
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	rocketim "rocket-im.local/server-sdk"
	"strings"
	"syscall"
	"time"
)

type session struct {
	ExternalUser string `json:"external_user"`
	Device       string `json:"device"`
	TokenSHA256  string `json:"token_sha256"`
}
type configuration struct {
	Listen           string    `json:"listen"`
	TLSCert          string    `json:"tls_cert"`
	TLSKey           string    `json:"tls_key"`
	ServiceURL       string    `json:"service_url"`
	Service          string    `json:"service"`
	CAFile           string    `json:"ca_file"`
	BusinessTokenEnv string    `json:"business_token_env"`
	Sessions         []session `json:"sessions"`
}
type backend struct {
	config configuration
	im     *rocketim.Client
}

func (b *backend) authenticate(r *http.Request) (session, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) != 64 {
		return session{}, false
	}
	sum := sha256.Sum256([]byte(token))
	for _, s := range b.config.Sessions {
		digest, _ := hex.DecodeString(s.TokenSHA256)
		if subtle.ConstantTimeCompare(sum[:], digest) == 1 {
			return s, true
		}
	}
	return session{}, false
}
func fail(w http.ResponseWriter, code string, status int) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
func (b *backend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil {
		fail(w, "tls_required", 426)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		w.WriteHeader(204)
		return
	}
	s, ok := b.authenticate(r)
	if !ok {
		fail(w, "unauthorized", 401)
		return
	}
	if r.Method != "POST" {
		fail(w, "not_found", 404)
		return
	}
	var input struct {
		RequestID    string `json:"request_id"`
		Device       string `json:"device"`
		IdentityKey  string `json:"identity_key"`
		TTLSeconds   int    `json:"ttl_seconds"`
		CredentialID string `json:"credential_id"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		fail(w, "invalid_request", 400)
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(w, "invalid_request", 400)
		return
	}
	if input.Device != s.Device {
		fail(w, "forbidden", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	// 稳定映射请求号由经过认证的业务身份派生；客户端不能指定external_user/account。
	hash := sha256.Sum256([]byte(s.ExternalUser))
	user, e := b.im.MapUser(ctx, rocketim.UserRequest{RequestID: "map_" + hex.EncodeToString(hash[:16]), ExternalUser: s.ExternalUser})
	var result any
	if e == nil {
		common := rocketim.UserRequest{RequestID: input.RequestID, ExternalUser: s.ExternalUser}
		switch r.URL.Path {
		case "/im/user":
			result = map[string]any{"user": user, "scope": rocketim.Scope{Service: b.config.Service, Account: user.Account, Device: s.Device}}
		case "/im/device":
			result, e = b.im.BindDevice(ctx, rocketim.DeviceRequest{UserRequest: common, Account: user.Account, Device: s.Device, IdentityKey: input.IdentityKey})
		case "/im/credential":
			result, e = b.im.IssueCredential(ctx, rocketim.CredentialRequest{UserRequest: common, Account: user.Account, Device: s.Device, TTLSeconds: input.TTLSeconds})
		case "/im/revoke":
			result, e = b.im.RevokeCredential(ctx, rocketim.RevokeRequest{UserRequest: common, Account: user.Account, Device: s.Device, CredentialID: input.CredentialID})
		default:
			fail(w, "not_found", 404)
			return
		}
	}
	if e != nil {
		var api *rocketim.APIError
		if errors.As(e, &api) {
			fail(w, api.Code, api.StatusCode)
		} else {
			fail(w, "im_unavailable", 503)
		}
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
func run() error {
	path := flag.String("config", "", "显式合成业务后台配置")
	flag.Parse()
	raw, e := os.ReadFile(*path)
	if e != nil {
		return errors.New("config_read_failed")
	}
	var c configuration
	if json.Unmarshal(raw, &c) != nil || len(c.Sessions) != 2 {
		return errors.New("invalid_config")
	}
	pem, e := os.ReadFile(c.CAFile)
	if e != nil {
		return errors.New("ca_read_failed")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid_ca")
	}
	client, e := rocketim.New(rocketim.Options{Endpoint: c.ServiceURL, Service: c.Service, BusinessToken: os.Getenv(c.BusinessTokenEnv), RootCAs: roots})
	if e != nil {
		return e
	}
	defer client.Close()
	for _, s := range c.Sessions {
		if len(s.TokenSHA256) != 64 || s.ExternalUser == "" || s.Device == "" {
			return errors.New("invalid_session_config")
		}
	}
	server := &http.Server{Addr: c.Listen, Handler: &backend{config: c, im: client}, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS(c.TLSCert, c.TLSKey) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("listen_failed")
		}
	}
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
