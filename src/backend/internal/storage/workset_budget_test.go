package storage

import (
	"context"
	m "rocket-im/service/internal/messaging"
	"sync"
	"testing"
)

// 填充仅为非E2EE内部PG行字节夹具；没有压低任何公开消息/请求限额。
func worksetPadding(t *testing.T, s *Store, remaining int64) {
	t.Helper()
	ctx := context.Background()
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result) VALUES('fixture','workset-padding','synthetic','{"pad":""}'::jsonb)`); e != nil {
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
	if _, e = tx.Exec(ctx, `UPDATE business_requests SET result=jsonb_build_object('pad',repeat('x',$1)) WHERE principal='fixture' AND request_id='workset-padding'`, evidenceLimit-u-r-remaining); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestWorksetMetadataAdmissionCannotStealExistingReserve(t *testing.T) {
	s := worksetStore(t)
	w := controlWorkset(t, s)
	worksetPadding(t, s, 0)
	ctx := context.Background()
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.CapacityWorkset(ctx, worksetToken, "prepare", &w)
	requireCode(t, e, "capacity_reserved")
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("metadata failure changed original", e)
	}
	out, e := s.CapacityWorkset(ctx, worksetToken, "query", nil)
	if e != nil || out != nil {
		t.Fatal("phantom workset", e)
	}
	sealClose(t, s)
}
func TestWorksetLastByteConcurrentOrdinaryWritesAndPhaseGrowth(t *testing.T) {
	s := worksetStore(t)
	w := controlWorkset(t, s)
	worksetCall(t, s, "prepare", &w, "prepared")
	worksetPadding(t, s, 1)
	ctx := context.Background()
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
			_, e = tx.Exec(ctx, `UPDATE business_requests SET result=jsonb_build_object('pad',result->>'pad'||'x') WHERE principal='fixture' AND request_id='workset-padding'`)
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
	if u+r != evidenceLimit || r < 2 || n != 1 {
		t.Fatal("missing phase/control reserve")
	}
	worksetCall(t, s, "confirm", &w, "confirmed")
	if _, e := s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
		t.Fatal(e)
	}
	u, r, n = reserveUsage(t, s)
	if u != evidenceLimit || r != 0 || n != 0 {
		t.Fatal("R not converted to U")
	}
	worksetCall(t, s, "settle", &w, "settled")
	u, r, n = reserveUsage(t, s)
	if u != evidenceLimit-2 || r != 0 || n != 0 {
		t.Fatal("terminal accounting")
	}
	sealClose(t, s)
}
