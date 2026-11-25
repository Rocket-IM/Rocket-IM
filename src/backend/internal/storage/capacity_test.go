package storage

import (
	"context"
	"encoding/json"
	"fmt"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/users"
	"strconv"
	"testing"
)

// 只为精确内部边界构造254条合成记录；真实256条E2EE验收由独立包装置执行。
func TestCapacityConcurrentLastMessageSlots(t *testing.T) {
	ctx := context.Background()
	s, c := evidenceStore(t)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	for i := 1; i <= 254; i++ {
		input := send(fmt.Sprintf("capacity-fixture-%d", i))
		raw, e := json.Marshal(input.Envelope)
		if e != nil {
			t.Fatal(e)
		}
		hash := m.Digest(raw)
		if _, e = tx.Exec(ctx, s.queries["insert_message"], 0, input.RequestID, input.Envelope.MessageID, i, raw, hash); e != nil {
			t.Fatal(e)
		}
		ack := m.Acceptance{RequestID: input.RequestID, MessageID: input.Envelope.MessageID, Sequence: strconv.Itoa(i), EnvelopeHash: hash}
		if e = s.append(ctx, tx, 1, m.Event{Kind: "message", Acceptance: ack, Envelope: &input.Envelope}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec(ctx, s.queries["accept"], 254); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	type result struct {
		input m.Send
		ack   m.Acceptance
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 3)
	for i := 0; i < 3; i++ {
		go func(i int) {
			<-start
			input := send(fmt.Sprintf("capacity-last-%d", i))
			ack, e := s.Accept(ctx, 0, input)
			results <- result{input, ack, e}
		}(i)
	}
	close(start)
	accepted := []result{}
	for i := 0; i < 3; i++ {
		r := <-results
		if r.err != nil {
			requireCode(t, r.err, "message_limit")
		} else {
			accepted = append(accepted, r)
		}
	}
	if len(accepted) != 2 || accepted[0].ack.Sequence == accepted[1].ack.Sequence {
		t.Fatal("last slots were not exclusive")
	}
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range accepted {
		ack, e := s.Accept(ctx, 0, r.input)
		if e != nil || ack != r.ack {
			t.Fatal("full quota lost precise acceptance", e)
		}
		bad := r.input
		bad.Envelope.Ciphertext = "00"
		_, e = s.Accept(ctx, 0, bad)
		requireCode(t, e, "idempotency_conflict")
	}
	_, e = s.Accept(ctx, 0, send("capacity-overflow"))
	requireCode(t, e, "message_limit")
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("rejected or repeated requests changed facts", e)
	}
	s.Close()
	if maintainOK(t, c, "reconcile", "").Digest != digestJSON(before) {
		t.Fatal("full quota reconciliation changed facts")
	}
	next := openOK(t, c)
	for _, r := range accepted {
		ack, e := next.Accept(ctx, 0, r.input)
		if e != nil || ack != r.ack {
			t.Fatal("full quota restart lost exact fact", e)
		}
	}
	sealClose(t, next)
}

func TestCapacityBusinessLedgerGlobalWithReconciliation(t *testing.T) {
	ctx := context.Background()
	original := freshBusiness(t)
	command, _ := bindBusiness(t, original, "capacity-buyer")
	credential := issueBusiness(t, original, command)
	c := guardConfig(t, original.Config)
	original.Close()
	maintainOK(t, c, "enroll", "")
	maintainOK(t, c, "enable-reconciliation", "")
	s := openOK(t, c)
	// 合成账本夹具只补到4095，不宣称4096次真实签发/吞吐验收；通过原事务维护证据。
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result)
	 SELECT 'shop','capacity-fixture-'||n,'synthetic','{}'::jsonb
	 FROM generate_series(1,4095-(SELECT COUNT(*)::integer FROM business_requests)) n`)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	request := users.Command{Service: "test", RequestID: "capacity-last", ExternalUser: "last-buyer"}
	last, e := s.Business(ctx, c.Business.Principals[1], "users", request)
	if e != nil {
		t.Fatal(e)
	}
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	request.RequestID = "capacity-overflow"
	_, e = s.Business(ctx, c.Business.Principals[0], "users", request)
	requireCode(t, e, "request_limit")
	request.RequestID = "capacity-last"
	again, e := s.Business(ctx, c.Business.Principals[1], "users", request)
	if e != nil || again.Account != last.Account {
		t.Fatal("original mapping unavailable at global quota", e)
	}
	command.RequestID = "issue-" + command.ExternalUser
	command.IdentityKey = ""
	command.TTLSeconds = 60
	issued, e := s.Business(ctx, c.Business.Principals[0], "credentials", command)
	if e != nil || issued.CredentialID != credential.CredentialID || issued.Token != credential.Token {
		t.Fatal("valid precise credential retry lost at capacity", e)
	}
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("business capacity refusal or retry changed facts", e)
	}
	s.Close()
	if maintainOK(t, c, "reconcile", "").Digest != digestJSON(before) {
		t.Fatal("business capacity reconciliation changed ledger")
	}
	next := openOK(t, c)
	_, e = next.Business(ctx, c.Business.Principals[0], "users", users.Command{Service: "test", RequestID: "still-full", ExternalUser: "last-buyer"})
	requireCode(t, e, "request_limit")
	sealClose(t, next)
}

func TestCapacityEvidenceBudgetRejectsUncommittedOversizeFixture(t *testing.T) {
	ctx := context.Background()
	s, c := evidenceStore(t)
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	// 故意超出公开业务输入的内部合成夹具，只测256MiB证据预算及事务回滚。
	// 分行生成避免把单个超大值交给协议入口；这不是合法业务容量或E2EE测试。
	_, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result)
	 SELECT 'synthetic','oversize-'||n,'synthetic',jsonb_build_object('padding',repeat('x',262144))
	 FROM generate_series(1,1025) n`)
	if e != nil {
		t.Fatal(e)
	}
	var size int64
	if e = tx.QueryRow(ctx, `SELECT sum(octet_length(to_jsonb(t)::text)) FROM business_requests t`).Scan(&size); e != nil || size <= 256*1024*1024 {
		t.Fatal("oversize fixture did not reach actual evidence budget", size, e)
	}
	t.Logf("synthetic row JSON bytes=%d, evidence budget=%d", size, 256*1024*1024)
	e = tx.Commit(ctx)
	requireCode(t, e, "maintenance_size_limit")
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("oversize evidence failure changed committed facts", e)
	}
	if e = s.Healthy(ctx); e != nil {
		t.Fatal("known rollback poisoned healthy prior state", e)
	}
	s.Close()
	if maintainOK(t, c, "reconcile", "").Digest != digestJSON(before) {
		t.Fatal("oversize rejected candidate corrupted original evidence")
	}
	next := openOK(t, c)
	ack, e := next.Accept(ctx, 0, send("after-oversize-rollback"))
	if e != nil || ack.Sequence != "1" {
		t.Fatal("rejected oversize did not preserve original capacity", e)
	}
	sealClose(t, next)
}
