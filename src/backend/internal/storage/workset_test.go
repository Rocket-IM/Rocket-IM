package storage

import (
	"context"
	m "rocket-im/service/internal/messaging"
	"strings"
	"sync"
	"testing"
)

const worksetToken = "workset-test-token-not-production"

func worksetStore(t *testing.T) *Store {
	t.Helper()
	c := testConfig(t)
	c.Devices[0].TokenSHA256 = m.Digest([]byte(worksetToken))
	c.Devices[1].TokenSHA256 = m.Digest([]byte(worksetToken + "-peer"))
	s := openOK(t, c)
	ctx := context.Background()
	if _, e := s.Material(ctx, 1, &m.Material{Identity: c.Identity(1), KeyPackage: "aabb"}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Welcome(ctx, 0, &m.Welcome{Welcome: "ccdd"}); e != nil {
		t.Fatal(e)
	}
	c = guardConfig(t, c)
	s.Close()
	maintainOK(t, c, "enroll", "")
	maintainOK(t, c, "enable-reconciliation", "")
	maintainOK(t, c, "enable-capacity-reserve", "")
	maintainOK(t, c, "enable-capacity-workset", "")
	s = openOK(t, c)
	knownControl(t, s)
	return s
}
func controlWorkset(t *testing.T, s *Store) m.CapacityWorkset {
	t.Helper()
	page, e := s.Page(context.Background(), 0, m.Poll{After: "0", Limit: 4})
	if e != nil || len(page.Events) == 0 {
		t.Fatal(e)
	}
	event := page.Events[0]
	a := event.Acceptance
	fields := [][]string{{event.Sequence, event.Kind, a.RequestID, a.MessageID, a.Sequence, a.EnvelopeHash, "initial"}}
	w := m.CapacityWorkset{Version: m.WorksetVersion, Owner: s.Config.Identity(0), SDKInstance: strings.Repeat("aa", 32), Conversation: s.Config.Conversation, Context: "initial", First: "1", Last: "1", OriginalsHash: m.WorksetHash([]any{"rocket-im/control-originals/1", fields})}
	w.ID = w.Digest()
	return w
}
func worksetCall(t *testing.T, s *Store, op string, w *m.CapacityWorkset, phase string) *m.CapacityWorksetState {
	t.Helper()
	out, e := s.CapacityWorkset(context.Background(), worksetToken, op, w)
	if e != nil || out == nil || out.Phase != phase || (w != nil && out.Workset != *w) {
		t.Fatalf("%s: %+v %v", op, out, e)
	}
	return out
}
func TestWorksetMigrationRejectsMissingOrNullPhase(t *testing.T) {
	s := worksetStore(t)
	ctx := context.Background()
	defer sealClose(t, s)
	for _, raw := range []string{`{}`, `{"workset":{}}`, `{"phase":null,"workset":{}}`, `{"phase":"prepared","workset":null}`, `{"phase":"active","workset":{}}`} {
		tx, e := s.Pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Exec(ctx, s.queries["workset_write"], 0, []byte(raw))
		_ = tx.Rollback(ctx)
		if e == nil {
			t.Fatal("migration accepted missing, null or SDK-only phase")
		}
	}
	out, e := s.CapacityWorkset(ctx, worksetToken, "query", nil)
	if e != nil || out != nil {
		t.Fatal("invalid fixtures changed original", e)
	}
}
func TestWorksetOriginalsConfirmationIdempotenceAndRestore(t *testing.T) {
	s := worksetStore(t)
	ctx := context.Background()
	w := controlWorkset(t, s)
	_, e := s.CapacityWorkset(ctx, worksetToken, "confirm", &w)
	requireCode(t, e, "workset_not_prepared")
	_, e = s.CapacityWorkset(ctx, worksetToken+"-peer", "prepare", &w)
	requireCode(t, e, "scope_mismatch")
	bad := w
	bad.OriginalsHash = strings.Repeat("bb", 32)
	bad.ID = bad.Digest()
	_, e = s.CapacityWorkset(ctx, worksetToken, "prepare", &bad)
	requireCode(t, e, "workset_original_mismatch")
	bad = w
	bad.Context = strings.Repeat("cc", 32)
	bad.ID = bad.Digest()
	_, e = s.CapacityWorkset(ctx, worksetToken, "prepare", &bad)
	requireCode(t, e, "workset_context_mismatch")
	worksetCall(t, s, "prepare", &w, "prepared")
	before, _ := s.readSnapshot(ctx)
	head := digestJSON(s.maintenance.state)
	worksetCall(t, s, "prepare", &w, "prepared")
	worksetCall(t, s, "query", nil, "prepared")
	after, _ := s.readSnapshot(ctx)
	if digestJSON(before) != digestJSON(after) || head != digestJSON(s.maintenance.state) {
		t.Fatal("exact retry wrote a second promise")
	}
	bad = w
	bad.SDKInstance = strings.Repeat("dd", 32)
	bad.ID = bad.Digest()
	_, e = s.CapacityWorkset(ctx, worksetToken, "prepare", &bad)
	requireCode(t, e, "workset_conflict")
	_, e = s.CapacityWorkset(ctx, worksetToken, "settle", &w)
	requireCode(t, e, "workset_not_confirmed")
	worksetCall(t, s, "confirm", &w, "confirmed")
	_, e = s.CapacityWorkset(ctx, worksetToken, "settle", &w)
	requireCode(t, e, "workset_not_complete")
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.CapacityWorkset(cancelled, worksetToken, "settle", &w); e == nil {
		t.Fatal("cancel succeeded")
	}
	c := s.Config
	sealClose(t, s)
	path := c.RecoveryState + ".workset-backup"
	maintainOK(t, c, "backup", path)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	maintainOK(t, target, "restore", path)
	s = openOK(t, target)
	worksetCall(t, s, "query", nil, "confirmed")
	if _, e = s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	worksetCall(t, s, "settle", &w, "settled")
	worksetCall(t, s, "prepare", &w, "settled")
	worksetCall(t, s, "confirm", &w, "settled")
	after, _ = s.readSnapshot(ctx)
	for i, table := range before.Tables {
		if table.Name != "alpha_devices" && table.Name != "alpha_mailbox" && table.Name != "service_maintenance" && digestJSON(table) != digestJSON(after.Tables[i]) {
			t.Fatal("original changed", table.Name)
		}
	}
	sealClose(t, s)
}

func TestWorksetUnknownCommitAllPhasesKeepPromise(t *testing.T) {
	for _, phase := range []string{"prepare", "confirm", "settle"} {
		t.Run(phase, func(t *testing.T) {
			s := worksetStore(t)
			ctx := context.Background()
			w := controlWorkset(t, s)
			if phase != "prepare" {
				worksetCall(t, s, "prepare", &w, "prepared")
			}
			if phase == "settle" {
				worksetCall(t, s, "confirm", &w, "confirmed")
				if _, e := s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
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
			out, e := s.capacityWorkset(ctx, tx, worksetToken, phase, &w)
			if out != nil {
				t.Fatal("unknown commit delivered success")
			}
			requireCode(t, e, "service_reconciliation_required")
			requireCode(t, s.Healthy(ctx), "service_reconciliation_required")
			c := s.Config
			s.Close()
			maintainOK(t, c, "reconcile", "")
			s = openOK(t, c)
			want := map[string]string{"prepare": "prepared", "confirm": "confirmed", "settle": "settled"}[phase]
			worksetCall(t, s, "query", nil, want)
			worksetCall(t, s, phase, &w, want)
			sealClose(t, s)
		})
	}
}

func TestWorksetConcurrentConflictingPrepareHasOneOwner(t *testing.T) {
	s := worksetStore(t)
	ctx := context.Background()
	w := controlWorkset(t, s)
	other := w
	other.SDKInstance = strings.Repeat("bb", 32)
	other.ID = other.Digest()
	start := make(chan struct{})
	result := make(chan error, 2)
	var wg sync.WaitGroup
	for _, input := range []m.CapacityWorkset{w, other} {
		wg.Add(1)
		go func(input m.CapacityWorkset) {
			defer wg.Done()
			<-start
			_, e := s.CapacityWorkset(ctx, worksetToken, "prepare", &input)
			result <- e
		}(input)
	}
	close(start)
	wg.Wait()
	close(result)
	success, conflict := 0, 0
	for e := range result {
		if e == nil {
			success++
		} else if m.ErrorCode(e) == "workset_conflict" {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal(success, conflict)
	}
	sealClose(t, s)
}
