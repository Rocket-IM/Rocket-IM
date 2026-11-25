package storage

import (
	"context"
	"reflect"
	m "rocket-im/service/internal/messaging"
	"sync"
	"testing"
)

func reserveStore(t *testing.T) *Store {
	s, c := evidenceStore(t)
	sealClose(t, s)
	maintainOK(t, c, "enable-capacity-reserve", "")
	return openOK(t, c)
}
func knownControl(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	if _, e := s.Accept(ctx, 0, send("reserve-original")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Processed(ctx, 1, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
}
func reserveUsage(t *testing.T, s *Store) (int64, int64, int64) {
	t.Helper()
	ctx := context.Background()
	tx, e := s.beginRead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	n, r, e := s.knownReserve(ctx, tx)
	if e != nil {
		t.Fatal(e)
	}
	u, e := snapshotRowBytes(ctx, tx)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	return u, r, n
}
func TestKnownReserveControlsExactRetryRestartAndBackup(t *testing.T) {
	ctx := context.Background()
	s := reserveStore(t)
	c := s.Config
	knownControl(t, s)
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	u, r, n := reserveUsage(t, s)
	if n != 1 || r <= 0 {
		t.Fatalf("invalid work %d %d", n, r)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.Processed(cancelled, 0, m.Processed{Sequence: "1", Disposition: "received"}); e == nil {
		t.Fatal("cancel succeeded")
	}
	after, e := s.readSnapshot(ctx)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("cancel changed original", e)
	}
	sealClose(t, s)
	s = openOK(t, c)
	u2, r2, n2 := reserveUsage(t, s)
	if u != u2 || r != r2 || n != n2 {
		t.Fatal("restart lost reservation")
	}
	sealClose(t, s)
	backup := c.RecoveryState + ".reserve-backup"
	maintainOK(t, c, "backup", backup)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	maintainOK(t, target, "restore", backup)
	s = openOK(t, target)
	_, r2, n2 = reserveUsage(t, s)
	if r2 != r || n2 != n {
		t.Fatal("backup lost reservation")
	}
	if _, e = s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	u2, r2, n2 = reserveUsage(t, s)
	if u2 != u+r || r2 != 0 || n2 != 0 {
		t.Fatalf("R->U drift %d+%d -> %d, R=%d", u, r, u2, r2)
	}
	before, e = s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	after, e = s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("retry mutated", e)
	}
	_, e = s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "context_retired"})
	requireCode(t, e, "disposition_conflict")
	sealClose(t, s)
}
func TestKnownReserveUnknownCommitKeepsOriginalAndMaintenanceGate(t *testing.T) {
	ctx := context.Background()
	s := reserveStore(t)
	knownControl(t, s)
	c := s.Config
	_, r, n := reserveUsage(t, s)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "UPDATE alpha_conversation SET welcome='known-reserve-test'"); e != nil {
		t.Fatal(e)
	}
	w := tx.(*evidencedTransaction)
	w.Tx = uncertainCommit{w.Tx}
	requireCode(t, tx.Commit(ctx), "service_reconciliation_required")
	requireCode(t, s.Healthy(ctx), "service_reconciliation_required")
	s.Close()
	maintainOK(t, c, "reconcile", "")
	s = openOK(t, c)
	_, r2, n2 := reserveUsage(t, s)
	if r != r2 || n != n2 {
		t.Fatal("unknown released promise")
	}
	sealClose(t, s)
}
func TestKnownReserveConcurrentLastByteNoOversell(t *testing.T) {
	ctx := context.Background()
	s := reserveStore(t)
	defer s.Close()
	knownControl(t, s)
	// 非E2EE/非公开可达业务输入：只填充生产PG行表示到真实256MiB门限。
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result) VALUES('fixture','reserve-padding','synthetic','{"pad":""}'::jsonb)`); e != nil {
		t.Fatal(e)
	}
	u, e := snapshotRowBytes(ctx, tx)
	if e != nil {
		t.Fatal(e)
	}
	_, r, e := s.knownReserve(ctx, tx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, `UPDATE business_requests SET result=jsonb_build_object('pad',repeat('x',$1)) WHERE principal='fixture' AND request_id='reserve-padding'`, evidenceLimit-u-r-1); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tx, e := s.begin(ctx)
			if e != nil {
				results <- e
				return
			}
			defer tx.Rollback(ctx)
			_, e = tx.Exec(ctx, `UPDATE business_requests SET result=jsonb_build_object('pad',result->>'pad'||'x') WHERE principal='fixture' AND request_id='reserve-padding'`)
			if e == nil {
				e = tx.Commit(ctx)
			}
			results <- e
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success, limited := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if m.ErrorCode(e) == "capacity_reserved" {
			limited++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || limited != 1 {
		t.Fatal("oversell", success, limited)
	}
	u, r, n := reserveUsage(t, s)
	if u+r != evidenceLimit || n != 1 {
		t.Fatal("promise lost")
	}
	if _, e = s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	u, r, n = reserveUsage(t, s)
	if u != evidenceLimit || r != 0 || n != 0 {
		t.Fatal("settlement failed")
	}
	sealClose(t, s)
}
