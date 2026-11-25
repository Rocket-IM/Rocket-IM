package rocketim

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type rejectingTransport struct{}

func (rejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("host_transport_must_not_be_used")
}

func TestClientOwnsTransportWhenHostReplacesDefault(t *testing.T) {
	prior := http.DefaultTransport
	http.DefaultTransport = rejectingTransport{}
	defer func() { http.DefaultTransport = prior }()
	c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"account":"account","external_user":"buyer"}`))
	}, 1, time.Second)
	if _, e := c.MapUser(context.Background(), UserRequest{RequestID: "r", ExternalUser: "buyer"}); e != nil {
		t.Fatal(e)
	}
}

func clientFor(t *testing.T, h http.HandlerFunc, attempts int, timeout time.Duration) *Client {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c, e := New(Options{Endpoint: server.URL, Service: "service", BusinessToken: "rimb_" + strings.Repeat("a", 64), RootCAs: roots, MaxAttempts: attempts, Timeout: timeout})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}
func TestResponseLossRetriesExactBytesAndNoRedirect(t *testing.T) {
	var count atomic.Int32
	var first string
	c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if count.Add(1) == 1 {
			first = string(body)
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		if string(body) != first {
			t.Error("changed retry bytes")
		}
		w.Write([]byte(`{"account":"account","external_user":"buyer"}`))
	}, 2, time.Second)
	u, e := c.MapUser(context.Background(), UserRequest{RequestID: "request", ExternalUser: "buyer"})
	if e != nil || u.Account != "account" || count.Load() != 2 {
		t.Fatal(u, e, count.Load())
	}
	var visited atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { visited.Add(1) }))
	defer other.Close()
	c2 := clientFor(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 307) }, 3, time.Second)
	_, e = c2.MapUser(context.Background(), UserRequest{})
	var api *APIError
	if !errors.As(e, &api) || api.StatusCode != 307 || visited.Load() != 0 {
		t.Fatal("redirect followed", e)
	}
}
func TestTypedErrorsCancellationAndBoundedRetries(t *testing.T) {
	for _, status := range []int{403, 409, 429, 503} {
		var count atomic.Int32
		c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(status)
			w.Write([]byte(`{"error":{"code":"forbidden"}}`))
		}, 3, time.Second)
		_, e := c.MapUser(context.Background(), UserRequest{})
		var api *APIError
		if !errors.As(e, &api) || api.Code != "forbidden" || api.StatusCode != status {
			t.Fatal(e)
		}
		want := int32(1)
		if status == 429 || status == 503 {
			want = 3
		}
		if count.Load() != want {
			t.Fatal("retry bound", count.Load())
		}
	}
	c := clientFor(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(100 * time.Millisecond):
		}
	}, 3, 30*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, e := c.MapUser(ctx, UserRequest{})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("deadline lost", e)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, e = c.MapUser(ctx2, UserRequest{})
	if !errors.Is(e, context.Canceled) {
		t.Fatal("cancel lost", e)
	}
}
func TestInvalidResponsesAndEndpoint(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"external_user":"other","account":"a"}`, strings.Repeat("a", 16385)} {
		c := clientFor(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }, 1, time.Second)
		if _, e := c.MapUser(context.Background(), UserRequest{ExternalUser: "buyer"}); e == nil {
			t.Fatal("invalid response accepted")
		}
	}
	for _, endpoint := range []string{"http://example.com", "https://user:password@example.com", "https://example.com?token=secret", "https://example.com/path"} {
		if _, e := New(Options{Endpoint: endpoint, Service: "a", BusinessToken: "rimb_" + strings.Repeat("a", 64)}); e == nil {
			t.Fatal("unsafe endpoint")
		}
	}
}
