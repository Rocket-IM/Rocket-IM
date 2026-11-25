// 本机验收代理：只制造传输故障，正常收发依旧由真实SDK和Go Service完成。
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"github.com/gorilla/websocket"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct{ Listen, Upstream, Cert, Key, CA, Control, Observations string }
type Fault struct {
	Mode         string          `json:"mode"`
	TokenHash    string          `json:"token_hash"`
	Consumed     bool            `json:"consumed"`
	Material     string          `json:"material"`
	Field        string          `json:"field"`
	Hits         int             `json:"hits"`
	WorksetReply json.RawMessage `json:"workset_reply,omitempty"`
}
type Envelope struct {
	Service       string `json:"service"`
	Conversation  string `json:"conversation"`
	SenderAccount string `json:"sender_account"`
	SenderDevice  string `json:"sender_device"`
	MessageID     string `json:"message_id"`
	Context       string `json:"context"`
	Ciphertext    string `json:"ciphertext"`
}
type Observation struct {
	Operation string `json:"operation"`
	Request   string `json:"request"`
	Hash      string `json:"body_hash"`
	TokenHash string `json:"token_hash"`
	AtMillis  int64  `json:"at_unix_ms"`
}

var mu sync.Mutex

func main() {
	path := flag.String("config", "", "fixture configuration")
	flag.Parse()
	raw, e := os.ReadFile(*path)
	if e != nil {
		panic("config read")
	}
	var c Config
	if json.Unmarshal(raw, &c) != nil {
		panic("config decode")
	}
	ca, e := os.ReadFile(c.CA)
	if e != nil {
		panic("ca read")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		panic("ca decode")
	}
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, HandshakeTimeout: 3 * time.Second}
	observations := []Observation{}
	slots := make(chan struct{}, 16)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "limit", 429)
			return
		}
		header := http.Header{}
		header.Set("Authorization", r.Header.Get("Authorization"))
		upstream, response, e := dialer.Dial(c.Upstream, header)
		if e != nil {
			if response != nil {
				_ = response.Body.Close()
				http.Error(w, "upstream_rejected", response.StatusCode)
			} else {
				http.Error(w, "unavailable", 503)
			}
			return
		}
		defer upstream.Close()
		up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}
		client, e := up.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer client.Close()
		client.SetReadLimit(600 * 1024)
		upstream.SetReadLimit(600 * 1024)
		for {
			_ = client.SetReadDeadline(time.Now().Add(20 * time.Second))
			kind, raw, e := client.ReadMessage()
			if e != nil {
				return
			}
			var req struct {
				Op   string          `json:"op"`
				Body json.RawMessage `json:"body"`
			}
			if json.Unmarshal(raw, &req) != nil {
				return
			}
			// 仅测试：在首次预约入库前让Service实际校验过期；不生成或替代密码材料。
			if req.Op == "recovery_reserve" {
				mu.Lock()
				var fault Fault
				if b, e := os.ReadFile(c.Control); e == nil {
					_ = json.Unmarshal(b, &fault)
				}
				if fault.Mode == "expire_recovery_reservation" && !fault.Consumed {
					var request map[string]json.RawMessage
					var body map[string]json.RawMessage
					_ = json.Unmarshal(raw, &request)
					_ = json.Unmarshal(request["body"], &body)
					body["deadline"] = json.RawMessage(`"1"`)
					request["body"], _ = json.Marshal(body)
					raw, _ = json.Marshal(request)
					fault.Consumed = true
					b, _ := json.Marshal(fault)
					_ = os.WriteFile(c.Control, b, 0o600)
				}
				mu.Unlock()
			}
			if strings.HasPrefix(req.Op, "capacity_workset_") && worksetRequestFault(c, r, req.Op) {
				time.Sleep(1500 * time.Millisecond)
				return
			}
			if req.Op == "send" || req.Op == "recovery_publish" || strings.HasPrefix(req.Op, "capacity_workset_") {
				var body struct {
					Request  string `json:"request_id"`
					Round    string `json:"id"`
					Material string `json:"kind"`
				}
				_ = json.Unmarshal(req.Body, &body)
				if req.Op == "recovery_publish" {
					body.Request = body.Round + ":" + body.Material
				}
				if strings.HasPrefix(req.Op, "capacity_workset_") {
					body.Request = body.Round
				}
				sum := sha256.Sum256(req.Body)
				mu.Lock()
				authorization := sha256.Sum256([]byte(r.Header.Get("Authorization")))
				observations = append(observations, Observation{req.Op, body.Request, hex.EncodeToString(sum[:]), hex.EncodeToString(authorization[:]), time.Now().UnixMilli()})
				b, _ := json.Marshal(observations)
				_ = os.WriteFile(c.Observations, b, 0o600)
				mu.Unlock()
			}
			_ = upstream.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if upstream.WriteMessage(kind, raw) != nil {
				return
			}
			_ = upstream.SetReadDeadline(time.Now().Add(4 * time.Second))
			kind, reply, e := upstream.ReadMessage()
			if e != nil {
				return
			}
			var response map[string]json.RawMessage
			_ = json.Unmarshal(reply, &response)
			mu.Lock()
			var fault Fault
			if b, e := os.ReadFile(c.Control); e == nil {
				_ = json.Unmarshal(b, &fault)
			}
			token := r.Header.Get("Authorization")
			if len(token) > 7 {
				token = token[7:]
			}
			sum := sha256.Sum256([]byte(token))
			target := fault.TokenHash == "" || fault.TokenHash == hex.EncodeToString(sum[:])
			var material struct {
				Kind string `json:"kind"`
			}
			_ = json.Unmarshal(req.Body, &material)
			recoveryFault := req.Op == "recovery_publish" && (fault.Material == "" || fault.Material == material.Kind) && (fault.Mode == "drop_recovery_ack" || fault.Mode == "delay_recovery_ack" || fault.Mode == "duplicate_recovery")
			active := target && !fault.Consumed && string(response["ok"]) == "true" && ((req.Op == "send" && (fault.Mode == "drop_send_ack" || fault.Mode == "delay_send_ack")) || (req.Op == "processed" && fault.Mode == "drop_processed_ack") || (req.Op == "poll" && fault.Mode == "tamper_message"))
			active = active || (target && !fault.Consumed && string(response["ok"]) == "true" && recoveryFault)
			worksetFault := strings.HasPrefix(req.Op, "capacity_workset_") && req.Op == fault.Field && (fault.Mode == "hold_workset_ack" || fault.Mode == "delay_workset_ack" || fault.Mode == "tamper_workset_ack" || fault.Mode == "replay_workset_ack")
			active = active || (target && !fault.Consumed && string(response["ok"]) == "true" && worksetFault)
			if active && fault.Mode == "replay_workset_ack" && json.Valid(fault.WorksetReply) {
				response["result"] = fault.WorksetReply
				reply, _ = json.Marshal(response)
			}
			if active && fault.Mode == "tamper_workset_ack" {
				var result map[string]json.RawMessage
				var workset map[string]json.RawMessage
				_ = json.Unmarshal(response["result"], &result)
				_ = json.Unmarshal(result["workset"], &workset)
				workset["sdk_instance"] = json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)
				result["workset"], _ = json.Marshal(workset)
				response["result"], _ = json.Marshal(result)
				reply, _ = json.Marshal(response)
			}
			var failure struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(response["error"], &failure)
			rejected := target && req.Op == "send" && string(response["ok"]) == "false" && failure.Code == "message_limit"
			active = active || (rejected && !fault.Consumed && (fault.Mode == "drop_send_rejection" || fault.Mode == "delay_send_rejection" || fault.Mode == "hold_send_rejection"))
			if target && !fault.Consumed && string(response["ok"]) == "true" && req.Op == "recovery_query" && fault.Mode == "tamper_recovery" {
				var round map[string]json.RawMessage
				if json.Unmarshal(response["result"], &round) == nil && round != nil {
					var reservation map[string]json.RawMessage
					_ = json.Unmarshal(round["reservation"], &reservation)
					field := fault.Field
					if field == "" {
						field = "request_hash"
					}
					switch field {
					case "service", "account", "device", "identity_key":
						var identity map[string]json.RawMessage
						_ = json.Unmarshal(reservation["target"], &identity)
						if field == "identity_key" {
							identity[field] = json.RawMessage(`"` + hex.EncodeToString(make([]byte, 32)) + `"`)
						} else {
							var scope map[string]json.RawMessage
							_ = json.Unmarshal(identity["scope"], &scope)
							scope[field] = json.RawMessage(`"other"`)
							identity["scope"], _ = json.Marshal(scope)
						}
						reservation["target"], _ = json.Marshal(identity)
					case "request_hash", "old_context", "previous":
						reservation[field] = json.RawMessage(`"` + hex.EncodeToString(make([]byte, 32)) + `"`)
					default:
						reservation[field] = json.RawMessage(`"other"`)
					}
					round["reservation"], _ = json.Marshal(reservation)
					response["result"], _ = json.Marshal(round)
					reply, _ = json.Marshal(response)
					active = true
				}
			}
			if active && fault.Mode == "tamper_message" {
				var page struct {
					Events []map[string]json.RawMessage `json:"events"`
				}
				_ = json.Unmarshal(response["result"], &page)
				active = false
				for _, event := range page.Events {
					if string(event["kind"]) != `"message"` {
						continue
					}
					var envelope Envelope
					if json.Unmarshal(event["envelope"], &envelope) != nil {
						continue
					}
					last := len(envelope.Ciphertext) - 2
					if envelope.Ciphertext[last:] == "00" {
						envelope.Ciphertext = envelope.Ciphertext[:last] + "01"
					} else {
						envelope.Ciphertext = envelope.Ciphertext[:last] + "00"
					}
					b, _ := json.Marshal(envelope)
					event["envelope"] = b
					digest := sha256.Sum256(b)
					var ack map[string]any
					_ = json.Unmarshal(event["acceptance"], &ack)
					ack["envelope_hash"] = hex.EncodeToString(digest[:])
					event["acceptance"], _ = json.Marshal(ack)
					active = true
					break
				}
				if active {
					var original map[string]json.RawMessage
					_ = json.Unmarshal(response["result"], &original)
					original["events"], _ = json.Marshal(page.Events)
					response["result"], _ = json.Marshal(original)
					reply, _ = json.Marshal(response)
				}
			}
			if active {
				fault.Consumed = fault.Mode != "hold_send_rejection" && fault.Mode != "hold_workset_ack"
				fault.Hits++
				b, _ := json.Marshal(fault)
				_ = os.WriteFile(c.Control, b, 0o600)
			}
			mu.Unlock()
			if active && (fault.Mode == "hold_send_rejection" || fault.Mode == "hold_workset_ack") {
				// 持续丢弃真实Service拒绝；每个连接仍有固定时限，由控制文件解除故障。
				time.Sleep(1500 * time.Millisecond)
				return
			}
			if active && (fault.Mode == "drop_send_ack" || fault.Mode == "drop_processed_ack" || fault.Mode == "drop_recovery_ack" || fault.Mode == "drop_send_rejection") {
				return
			}
			if active && (fault.Mode == "delay_send_ack" || fault.Mode == "delay_recovery_ack" || fault.Mode == "delay_send_rejection" || fault.Mode == "delay_workset_ack") {
				time.Sleep(1500 * time.Millisecond)
			}
			if active && fault.Mode == "duplicate_recovery" {
				if upstream.WriteMessage(websocket.TextMessage, raw) != nil {
					return
				}
				var body struct {
					Round    string `json:"id"`
					Material string `json:"kind"`
				}
				_ = json.Unmarshal(req.Body, &body)
				digest := sha256.Sum256(req.Body)
				authorization := sha256.Sum256([]byte(r.Header.Get("Authorization")))
				mu.Lock()
				observations = append(observations, Observation{req.Op, body.Round + ":" + body.Material, hex.EncodeToString(digest[:]), hex.EncodeToString(authorization[:]), time.Now().UnixMilli()})
				record, _ := json.Marshal(observations)
				_ = os.WriteFile(c.Observations, record, 0o600)
				mu.Unlock()
				_, again, e := upstream.ReadMessage()
				if e != nil {
					return
				}
				var second map[string]json.RawMessage
				if json.Unmarshal(again, &second) != nil || string(second["ok"]) != "true" {
					return
				}
				reply = again
			}
			_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if client.WriteMessage(kind, reply) != nil {
				return
			}
		}
	})
	server := http.Server{Addr: c.Listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	if server.ListenAndServeTLS(c.Cert, c.Key) != nil {
		os.Exit(1)
	}
}

func worksetRequestFault(c Config, r *http.Request, op string) bool {
	mu.Lock()
	defer mu.Unlock()
	var fault Fault
	if b, e := os.ReadFile(c.Control); e == nil {
		_ = json.Unmarshal(b, &fault)
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest := sha256.Sum256([]byte(token))
	if fault.Mode != "hold_workset_request" || fault.Field != op || (fault.TokenHash != "" && fault.TokenHash != hex.EncodeToString(digest[:])) {
		return false
	}
	fault.Hits++
	b, _ := json.Marshal(fault)
	_ = os.WriteFile(c.Control, b, 0600)
	return true
}
