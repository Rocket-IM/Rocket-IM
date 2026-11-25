// 独立包验收入口，仅调用公开SDK；不导入Service、不连接数据库。
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	rocketim "rocket-im.local/server-sdk"
	"time"
)

func main() {
	var c struct {
		Endpoint, Service, Token, CA string
		TimeoutMS, Attempts          int
	}
	raw, e := os.ReadFile(os.Args[1])
	if e != nil || json.Unmarshal(raw, &c) != nil {
		panic("invalid_test_config")
	}
	pem, e := os.ReadFile(c.CA)
	if e != nil {
		panic("invalid_test_ca")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid_test_ca")
	}
	client, e := rocketim.New(rocketim.Options{Endpoint: c.Endpoint, Service: c.Service, BusinessToken: c.Token, RootCAs: roots, Timeout: time.Duration(c.TimeoutMS) * time.Millisecond, MaxAttempts: c.Attempts})
	if e != nil {
		panic("invalid_test_client")
	}
	defer client.Close()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16384)
	for scanner.Scan() {
		var r struct {
			Op         string          `json:"op"`
			Body       json.RawMessage `json:"body"`
			DeadlineMS int             `json:"deadline_ms"`
		}
		if json.Unmarshal(scanner.Bytes(), &r) != nil {
			panic("invalid_test_request")
		}
		ctx := context.Background()
		cancel := func() {}
		if r.DeadlineMS != 0 {
			ctx, cancel = context.WithTimeout(ctx, time.Duration(r.DeadlineMS)*time.Millisecond)
		}
		var out any
		switch r.Op {
		case "worksets":
			out, e = client.CapacityWorksets(ctx)
		case "capacity":
			out, e = client.Capacity(ctx)
		case "users":
			var input rocketim.UserRequest
			e = json.Unmarshal(r.Body, &input)
			if e == nil {
				out, e = client.MapUser(ctx, input)
			}
		case "devices":
			var input rocketim.DeviceRequest
			e = json.Unmarshal(r.Body, &input)
			if e == nil {
				out, e = client.BindDevice(ctx, input)
			}
		case "credentials":
			var input rocketim.CredentialRequest
			e = json.Unmarshal(r.Body, &input)
			if e == nil {
				out, e = client.IssueCredential(ctx, input)
			}
		case "revocations":
			var input rocketim.RevokeRequest
			e = json.Unmarshal(r.Body, &input)
			if e == nil {
				out, e = client.RevokeCredential(ctx, input)
			}
		default:
			e = errors.New("unknown_op")
		}
		cancel()
		code := ""
		if e != nil {
			var api *rocketim.APIError
			switch {
			case errors.As(e, &api):
				code = api.Code
			case errors.Is(e, context.DeadlineExceeded):
				code = "deadline_exceeded"
			case errors.Is(e, context.Canceled):
				code = "cancelled"
			default:
				code = "transport_failed"
			}
			out = nil
		}
		response, _ := json.Marshal(map[string]any{"ok": e == nil, "code": code, "result": out})
		fmt.Println(string(response))
	}
}
