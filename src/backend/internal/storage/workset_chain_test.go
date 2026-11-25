package storage

import (
	"context"
	"encoding/json"
	m "rocket-im/service/internal/messaging"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func repeatedWorksetStore(t *testing.T) *Store {
	t.Helper()
	s := worksetStore(t)
	c := s.Config
	sealClose(t, s)
	maintainOK(t, c, "enable-repeated-workset", "")
	maintainOK(t, c, "enable-repeated-workset", "")
	return openOK(t, c)
}
func finishWorkset(t *testing.T, s *Store, w m.CapacityWorkset) {
	t.Helper()
	worksetCall(t, s, "prepare", &w, "prepared")
	worksetCall(t, s, "confirm", &w, "confirmed")
	if _, e := s.Processed(context.Background(), 0, m.Processed{Sequence: w.Last, Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	worksetCall(t, s, "settle", &w, "settled")
}
func followingWorkset(t *testing.T, s *Store, previous m.CapacityWorkset) m.CapacityWorkset {
	t.Helper()
	ctx := context.Background()
	last, _ := m.Number(previous.Last)
	sequence := strconv.FormatInt(last+1, 10)
	if _, e := s.Accept(ctx, 0, send("repeat-original-"+sequence)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Processed(ctx, 1, m.Processed{Sequence: sequence, Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	page, e := s.Page(ctx, 0, m.Poll{After: previous.Last, Limit: 4})
	if e != nil || len(page.Events) != 1 {
		t.Fatal("next control", e)
	}
	event := page.Events[0]
	a := event.Acceptance
	fields := [][]string{{event.Sequence, event.Kind, a.RequestID, a.MessageID, a.Sequence, a.EnvelopeHash, "initial"}}
	w := previous
	w.Version = m.WorksetChainVersion
	w.Previous = previous.ID
	w.First = sequence
	w.Last = sequence
	w.OriginalsHash = m.WorksetHash([]any{"rocket-im/control-originals/1", fields})
	w.ID = w.Digest()
	return w
}
func worksetHistory(t *testing.T, s *Store) []m.CapacityWorksetState {
	t.Helper()
	ctx := context.Background()
	tx, e := s.beginRead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, history, e := s.readWorksetChain(ctx, tx, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return history
}

func TestRepeatedWorksetsThreeDistinctOriginalsAndHistoricalRetries(t *testing.T) {
	s := repeatedWorksetStore(t)
	ctx := context.Background()
	first := controlWorkset(t, s)
	worksetCall(t, s, "prepare", &first, "prepared")
	second := followingWorkset(t, s, first)
	before, _ := s.readSnapshot(ctx)
	_, e := s.CapacityWorkset(ctx, worksetToken, "prepare", &second)
	requireCode(t, e, "workset_not_settled")
	after, _ := s.readSnapshot(ctx)
	if digestJSON(before) != digestJSON(after) {
		t.Fatal("unsettled predecessor replaced")
	}
	finishWorkset(t, s, first)
	worksetCall(t, s, "prepare", &second, "prepared")
	if len(worksetHistory(t, s)) != 1 {
		t.Fatal("lost terminal predecessor")
	}
	for _, op := range []string{"prepare", "confirm", "settle"} {
		worksetCall(t, s, op, &first, "settled")
	}
	worksetCall(t, s, "query", nil, "prepared")
	for _, field := range []string{"previous", "instance", "overlap", "context", "original", "id"} {
		bad := second
		switch field {
		case "previous":
			bad.Previous = strings.Repeat("ff", 32)
		case "instance":
			bad.SDKInstance = strings.Repeat("ff", 32)
		case "overlap":
			bad.First = "1"
		case "context":
			bad.Context = strings.Repeat("ff", 32)
		case "original":
			bad.OriginalsHash = strings.Repeat("ff", 32)
		case "id":
			bad.Previous = first.ID
			bad.Last = "3"
		}
		if field != "id" {
			bad.ID = bad.Digest()
		}
		if _, e = s.CapacityWorkset(ctx, worksetToken, "prepare", &bad); e == nil {
			t.Fatal("conflicting successor accepted", field)
		}
	}
	finishWorkset(t, s, second)
	third := followingWorkset(t, s, second)
	worksetCall(t, s, "prepare", &third, "prepared")
	before, _ = s.readSnapshot(ctx)
	for _, w := range []m.CapacityWorkset{first, second} {
		for _, op := range []string{"prepare", "confirm", "settle"} {
			worksetCall(t, s, op, &w, "settled")
		}
	}
	after, _ = s.readSnapshot(ctx)
	if digestJSON(before) != digestJSON(after) {
		t.Fatal("historical retry mutated current/history")
	}
	c := s.Config
	sealClose(t, s)
	path := c.RecoveryState + ".repeat-backup"
	maintainOK(t, c, "backup", path)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	maintainOK(t, target, "restore", path)
	s = openOK(t, target)
	h := worksetHistory(t, s)
	if len(h) != 2 || h[0].Workset != first || h[1].Workset != second {
		t.Fatal("full restore lost historical originals")
	}
	finishWorkset(t, s, third)
	sealClose(t, s)
}

func TestRepeatedWorksetNewMetadataCannotConsumeExistingReservedControls(t *testing.T) {
	s := repeatedWorksetStore(t)
	defer sealClose(t, s)
	ctx := context.Background()
	first := controlWorkset(t, s)
	finishWorkset(t, s, first)
	second := followingWorkset(t, s, first)
	worksetPadding(t, s, 0)
	before, _ := s.readSnapshot(ctx)
	_, e := s.CapacityWorkset(ctx, worksetToken, "prepare", &second)
	requireCode(t, e, "capacity_reserved")
	after, _ := s.readSnapshot(ctx)
	if digestJSON(before) != digestJSON(after) || len(worksetHistory(t, s)) != 0 {
		t.Fatal("rejected next stole reservation/history")
	}
	if _, e = s.Processed(ctx, 0, m.Processed{Sequence: second.Last, Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	worksetCall(t, s, "prepare", &first, "settled")
	u, r, _ := reserveUsage(t, s)
	if u != evidenceLimit || r != 0 {
		t.Fatal("known control cannot consume original R")
	}
}

func TestRepeatedWorksetUnknownCommitPreservesCompleteHistory(t *testing.T) {
	for _, operation := range []string{"prepare", "confirm", "settle"} {
		t.Run(operation, func(t *testing.T) {
			s := repeatedWorksetStore(t)
			ctx := context.Background()
			first := controlWorkset(t, s)
			finishWorkset(t, s, first)
			w := followingWorkset(t, s, first)
			if operation != "prepare" {
				worksetCall(t, s, "prepare", &w, "prepared")
			}
			if operation == "settle" {
				worksetCall(t, s, "confirm", &w, "confirmed")
				if _, e := s.Processed(ctx, 0, m.Processed{Sequence: w.Last, Disposition: "received"}); e != nil {
					t.Fatal(e)
				}
			}
			tx, e := s.begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			wrapped := tx.(*evidencedTransaction)
			wrapped.Tx = uncertainCommit{wrapped.Tx}
			out, e := s.capacityWorkset(ctx, tx, worksetToken, operation, &w)
			if out != nil {
				t.Fatal("unknown commit returned success")
			}
			requireCode(t, e, "service_reconciliation_required")
			c := s.Config
			s.Close()
			maintainOK(t, c, "reconcile", "")
			s = openOK(t, c)
			history := worksetHistory(t, s)
			if len(history) != 1 || history[0].Workset != first {
				t.Fatal("unknown candidate lost original predecessor")
			}
			worksetCall(t, s, operation, &w, map[string]string{"prepare": "prepared", "confirm": "confirmed", "settle": "settled"}[operation])
			sealClose(t, s)
		})
	}
}

func TestRepeatedWorksetMigrationAndMalformedHistoryRollback(t *testing.T) {
	s := repeatedWorksetStore(t)
	defer sealClose(t, s)
	first := controlWorkset(t, s)
	finishWorkset(t, s, first)
	second := followingWorkset(t, s, first)
	worksetCall(t, s, "prepare", &second, "prepared")
	ctx := context.Background()
	for _, raw := range []string{`null`, `{}`, `[{}]`, `[]`, strings.Repeat(" ", 1)} {
		tx, e := s.Pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, `UPDATE alpha_devices SET capacity_workset_history=$1::jsonb WHERE device_index=0`, raw)
		if e == nil {
			_, _, e = s.readWorksetChain(ctx, tx, 0)
		}
		_ = tx.Rollback(ctx)
		if e == nil {
			t.Fatal("accepted invalid or erased predecessor", raw)
		}
	}
	h := worksetHistory(t, s)
	b, _ := json.Marshal(h)
	if len(h) != 1 || !strings.Contains(string(b), first.ID) {
		t.Fatal("history changed")
	}
}

func TestRepeatedWorksetSettlementRacesNextPreparation(t *testing.T) {
	s := repeatedWorksetStore(t)
	defer sealClose(t, s)
	ctx := context.Background()
	first := controlWorkset(t, s)
	worksetCall(t, s, "prepare", &first, "prepared")
	worksetCall(t, s, "confirm", &first, "confirmed")
	if _, e := s.Processed(ctx, 0, m.Processed{Sequence: first.Last, Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	next := followingWorkset(t, s, first)
	start := make(chan struct{})
	var settlement, preparation error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, settlement = s.CapacityWorkset(ctx, worksetToken, "settle", &first)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, preparation = s.CapacityWorkset(ctx, worksetToken, "prepare", &next)
	}()
	close(start)
	wg.Wait()
	if settlement != nil {
		t.Fatal(settlement)
	}
	if preparation != nil {
		requireCode(t, preparation, "workset_not_settled")
	}
	worksetCall(t, s, "prepare", &next, "prepared")
	history := worksetHistory(t, s)
	if len(history) != 1 || history[0].Workset != first || history[0].Phase != "settled" {
		t.Fatal("concurrent handoff lost terminal proof")
	}
	cap, e := s.CapacityDevice(ctx, worksetToken)
	if e != nil || cap.Schema != "8" || cap.Reserve.State != "bounded_ready" {
		t.Fatal("schema8 diagnostic lost policy", e)
	}
}
