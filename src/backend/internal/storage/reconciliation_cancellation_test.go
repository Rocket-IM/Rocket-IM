package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReconciliationCancelledAdmissionDoesNotPoisonService(t *testing.T) {
	s, _ := evidenceStore(t)
	for range 24 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		e := s.Healthy(ctx)
		if !errors.Is(e, context.Canceled) {
			t.Fatal("cancelled admission changed gate", e)
		}
		if e = s.Healthy(context.Background()); e != nil {
			t.Fatal("cancelled request poisoned Service", e)
		}
	}
	sealClose(t, s)
}

func TestReconciliationCancelledPreflightRollsBackWithoutPoison(t *testing.T) {
	s, _ := evidenceStore(t)
	ctx := context.Background()
	lock, e := s.Pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(ctx)
	if _, e = lock.Exec(ctx, "LOCK TABLE alpha_messages IN ACCESS EXCLUSIVE MODE"); e != nil {
		t.Fatal(e)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	_, e = s.Accept(short, 0, send("cancelled-preflight"))
	cancel()
	if e == nil {
		t.Fatal("blocked preflight did not cancel")
	}
	if e = lock.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Healthy(ctx); e != nil {
		t.Fatal("preflight cancellation poisoned Service", e)
	}
	ack, e := s.Accept(ctx, 0, send("after-cancel"))
	if e != nil || ack.Sequence != "1" {
		t.Fatal("cancelled attempt fabricated acceptance", e)
	}
	sealClose(t, s)
}

func TestReconciliationConflictingRequestDoesNotAdvanceEvidence(t *testing.T) {
	s, _ := evidenceStore(t)
	ctx := context.Background()
	if _, e := s.Accept(ctx, 0, send("exact")); e != nil {
		t.Fatal(e)
	}
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	state := digestJSON(s.maintenance.state)
	conflict := send("exact")
	conflict.Envelope.Ciphertext = "abce"
	_, e = s.Accept(ctx, 0, conflict)
	requireCode(t, e, "idempotency_conflict")
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) || digestJSON(s.maintenance.state) != state {
		t.Fatal("conflict advanced persistent facts", e)
	}
	sealClose(t, s)
}
