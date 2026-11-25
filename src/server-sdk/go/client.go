package rocketim

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Options struct {
	Endpoint      string
	Service       string
	BusinessToken string
	// RootCAs为nil时使用系统根。非nil时New复制证书池，调用者仍持有原池。
	RootCAs *x509.CertPool
	// Timeout是每次HTTP尝试的上限，默认5秒，范围1毫秒到30秒。
	Timeout time.Duration
	// MaxAttempts默认2，范围1到3。仅重试传输失败、429、503；等待可取消。
	MaxAttempts int
}

// Client可并发使用。调用者通过context管理总时限；Close回收空闲连接。
type Client struct {
	endpoint, service, token string
	attempts                 int
	http                     *http.Client
}

func New(o Options) (*Client, error) {
	u, e := url.Parse(o.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || o.Service == "" || !strings.HasPrefix(o.BusinessToken, "rimb_") || len(o.BusinessToken) != 69 {
		return nil, errors.New("rocket-im: invalid_options")
	}
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Second
	}
	if o.MaxAttempts == 0 {
		o.MaxAttempts = 2
	}
	if o.Timeout < time.Millisecond || o.Timeout > 30*time.Second || o.MaxAttempts < 1 || o.MaxAttempts > 3 {
		return nil, errors.New("rocket-im: invalid_options")
	}
	var roots *x509.CertPool
	if o.RootCAs != nil {
		roots = o.RootCAs.Clone()
	}
	// 不依赖宿主可替换的全局DefaultTransport类型，也不继承其TLS绕过设置。
	t := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxIdleConns: 16, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 3 * time.Second, ExpectContinueTimeout: time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	return &Client{endpoint: strings.TrimRight(o.Endpoint, "/"), service: o.Service, token: o.BusinessToken, attempts: o.MaxAttempts, http: &http.Client{Transport: t, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) MapUser(ctx context.Context, r UserRequest) (User, error) {
	var out User
	e := c.call(ctx, "users", struct {
		Service string `json:"service"`
		UserRequest
	}{c.service, r}, &out)
	if e == nil && (out.Account == "" || out.ExternalUser != r.ExternalUser) {
		e = errors.New("rocket-im: invalid_response")
	}
	return out, e
}
func (c *Client) BindDevice(ctx context.Context, r DeviceRequest) (DeviceBinding, error) {
	var out DeviceBinding
	e := c.call(ctx, "devices", struct {
		Service string `json:"service"`
		DeviceRequest
	}{c.service, r}, &out)
	if e == nil {
		e = c.checkBinding(out, r.ExternalUser, r.Account, r.Device)
		if e == nil && out.Identity.IdentityKey != r.IdentityKey {
			e = errors.New("rocket-im: invalid_response")
		}
	}
	return out, e
}
func (c *Client) IssueCredential(ctx context.Context, r CredentialRequest) (Credential, error) {
	var out Credential
	e := c.call(ctx, "credentials", struct {
		Service string `json:"service"`
		CredentialRequest
	}{c.service, r}, &out)
	if e == nil {
		e = c.checkBinding(out.DeviceBinding, r.ExternalUser, r.Account, r.Device)
		if e == nil && (out.CredentialID == "" || out.Token == "" || out.ExpiresAt.IsZero()) {
			e = errors.New("rocket-im: invalid_response")
		}
	}
	return out, e
}
func (c *Client) RevokeCredential(ctx context.Context, r RevokeRequest) (Revocation, error) {
	var out Revocation
	e := c.call(ctx, "revocations", struct {
		Service string `json:"service"`
		RevokeRequest
	}{c.service, r}, &out)
	if e == nil {
		e = c.checkBinding(out.DeviceBinding, r.ExternalUser, r.Account, r.Device)
		if e == nil && (!out.Revoked || out.CredentialID != r.CredentialID) {
			e = errors.New("rocket-im: invalid_response")
		}
	}
	return out, e
}
func (c *Client) checkBinding(b DeviceBinding, external, account, device string) error {
	if b.Account != account || b.ExternalUser != external || b.Identity.Scope != (Scope{Service: c.service, Account: account, Device: device}) || b.Identity.IdentityKey == "" || b.Conversation == "" {
		return errors.New("rocket-im: invalid_response")
	}
	return nil
}
func (c *Client) call(ctx context.Context, op string, input, output any) error {
	body, e := json.Marshal(input)
	if e != nil {
		return e
	}
	return c.callHTTP(ctx, http.MethodPost, op, body, output)
}
func (c *Client) callHTTP(ctx context.Context, method, op string, body []byte, output any) error {
	for attempt := 0; attempt < c.attempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * 50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, e := http.NewRequestWithContext(ctx, method, c.endpoint+"/v1/business/"+op, bytes.NewReader(body))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		response, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			e = fmt.Errorf("rocket-im: transport_failed: %w", err)
			if attempt+1 < c.attempts {
				continue
			}
			return e
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		response.Body.Close()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt+1 < c.attempts {
				continue
			}
			return fmt.Errorf("rocket-im: response_failed: %w", err)
		}
		if len(raw) > 16384 {
			return errors.New("rocket-im: response_too_large")
		}
		if response.StatusCode != http.StatusOK {
			var envelope struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			code := "http_error"
			if json.Unmarshal(raw, &envelope) == nil && knownCode(envelope.Error.Code) {
				code = envelope.Error.Code
			}
			e = &APIError{StatusCode: response.StatusCode, Code: code}
			if (response.StatusCode == 429 || response.StatusCode == 503) && attempt+1 < c.attempts {
				continue
			}
			return e
		}
		if e = json.Unmarshal(raw, output); e != nil {
			return errors.New("rocket-im: invalid_response")
		}
		return nil
	}
	return errors.New("rocket-im: attempts_exhausted")
}
func knownCode(s string) bool {
	switch s {
	case "unauthorized", "forbidden", "scope_mismatch", "invalid_request", "idempotency_conflict", "device_conflict", "device_limit", "device_not_bound", "request_limit", "credential_expired", "credential_revoked", "invalid_expiry", "storage_unavailable", "service_reconciliation_required", "service_reconciliation_mismatch":
		return true
	}
	return false
}
