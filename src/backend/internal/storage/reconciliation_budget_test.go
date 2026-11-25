package storage

import (
	"context"
	"encoding/json"
	"fmt"
	m "rocket-im/service/internal/messaging"
	"strconv"
	"strings"
	"testing"
)

func TestReconciliationEvidenceDoesNotLowerMessageLimitToBackupBudget(t *testing.T) {
	ctx := context.Background()
	s, c := evidenceStore(t)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	// 构造有界的大型合成原件夹具；这不是E2EE或吞吐量验收。
	for i := 1; i <= 180; i++ {
		input := send(fmt.Sprintf("large-%d", i))
		input.Envelope.Ciphertext = strings.Repeat("ab", 96*1024)
		raw, e := json.Marshal(input.Envelope)
		if e != nil {
			t.Fatal(e)
		}
		digest := m.Digest(raw)
		if _, e = tx.Exec(ctx, s.queries["insert_message"], 0, input.RequestID, input.Envelope.MessageID, i, raw, digest); e != nil {
			t.Fatal(e)
		}
		ack := m.Acceptance{RequestID: input.RequestID, MessageID: input.Envelope.MessageID, Sequence: strconv.Itoa(i), EnvelopeHash: digest}
		if e = s.append(ctx, tx, 1, m.Event{Kind: "message", Acceptance: ack, Envelope: &input.Envelope}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec(ctx, s.queries["accept"], 180); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal("valid evidence constrained by backup budget", e)
	}
	ack, e := s.Accept(ctx, 0, send("after-large-state"))
	if e != nil || ack.Sequence != "181" {
		t.Fatal("existing message quota reduced", e)
	}
	s.Close()
	maintainOK(t, c, "reconcile", "")
	_, e = Maintain(ctx, c, "backup", c.RecoveryState+".oversize")
	requireCode(t, e, "maintenance_size_limit")
	next := openOK(t, c)
	again, e := next.Accept(ctx, 0, send("after-large-state"))
	if e != nil || again != ack {
		t.Fatal("large original acceptance lost", e)
	}
	sealClose(t, next)
}
