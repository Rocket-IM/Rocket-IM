package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"sync"
	"testing"
	"time"
)

func evidenceStore(t *testing.T) (*Store, config.Config) {
	t.Helper()
	original := testStore(t)
	c := guardConfig(t, original.Config)
	original.Close()
	maintainOK(t, c, "enroll", "")
	maintainOK(t, c, "enable-reconciliation", "")
	return openOK(t, c), c
}

func TestReconciliationCrashExactFactsAndBackup(t *testing.T) {
	ctx := context.Background()
	s, c := evidenceStore(t)
	ack, e := s.Accept(ctx, 0, send("survivor"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Processed(ctx, 1, m.Processed{Sequence: "1"}); e != nil {
		t.Fatal(e)
	}
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	_, e = Open(ctx, c)
	requireCode(t, e, "service_reconciliation_required")
	_, e = Maintain(ctx, c, "backup", c.RecoveryState+".live")
	requireCode(t, e, "service_reconciliation_required")
	result := maintainOK(t, c, "reconcile", "")
	if result.Version != reconciliationVersion || result.Digest != digestJSON(before) {
		t.Fatal("changed complete facts")
	}
	if again := maintainOK(t, c, "reconcile", ""); again != result {
		t.Fatal("repeat reconcile changed checkpoint")
	}
	path := c.RecoveryState + ".backup"
	maintainOK(t, c, "backup", path)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	maintainOK(t, target, "restore", path)
	maintainOK(t, target, "restore", path)
	_, e = Maintain(ctx, c, "reconcile", "")
	requireCode(t, e, "maintenance_target_mismatch")
	next := openOK(t, target)
	again, e := next.Accept(ctx, 0, send("survivor"))
	if e != nil || again != ack {
		t.Fatal("changed exact request", e)
	}
	page, e := next.Page(ctx, 0, m.Poll{After: "0", Limit: 4})
	if e != nil || len(page.Events) != 1 || page.Events[0].Kind != "delivered" {
		t.Fatal("lost device event", e)
	}
	sealClose(t, next)
}

func TestReconciliationRequiresPriorEvidenceAndUpgrade(t *testing.T) {
	ctx := context.Background()
	c := guardConfig(t, testConfig(t))
	maintainOK(t, c, "enroll", "")
	s := openOK(t, c)
	s.Close()
	_, e := Maintain(ctx, c, "reconcile", "")
	requireCode(t, e, "service_reconciliation_evidence_missing")
	_, e = Maintain(ctx, c, "enable-reconciliation", "")
	requireCode(t, e, "service_reconciliation_required")
	// 不能为既有running补造此前不存在的证据；另建可信正常封存夹具验证升级。
	old := testStore(t)
	c = guardConfig(t, old.Config)
	ack, e := old.Accept(ctx, 0, send("schema4"))
	if e != nil {
		t.Fatal(e)
	}
	old.Close()
	maintainOK(t, c, "enroll", "")
	path := c.RecoveryState + ".old"
	maintainOK(t, c, "backup", path)
	result := maintainOK(t, c, "enable-reconciliation", "")
	if again := maintainOK(t, c, "enable-reconciliation", ""); again != result {
		t.Fatal("repeat enable")
	}
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	_, e = Maintain(ctx, target, "restore", path)
	requireCode(t, e, "service_backup_version_unsupported")
	next := openOK(t, c)
	again, e := next.Accept(ctx, 0, send("schema4"))
	if e != nil || again != ack {
		t.Fatal("upgrade discarded old facts", e)
	}
	sealClose(t, next)
}

// 模拟数据库已提交但调用方未收到提交结果。实现路径仍是原evidencedTransaction.Commit。
type uncertainCommit struct{ pgx.Tx }

func (tx uncertainCommit) Commit(ctx context.Context) error {
	if e := tx.Tx.Commit(ctx); e != nil {
		return e
	}
	return errors.New("synthetic lost commit result")
}

func TestReconciliationUnknownCommitBlocksAllAccess(t *testing.T) {
	ctx := context.Background()
	s, c := evidenceStore(t)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "UPDATE alpha_conversation SET welcome='aaff'"); e != nil {
		t.Fatal(e)
	}
	w := tx.(*evidencedTransaction)
	w.Tx = uncertainCommit{w.Tx}
	requireCode(t, tx.Commit(ctx), "service_reconciliation_required")
	_, e = s.Page(ctx, 1, m.Poll{After: "0", Limit: 4})
	requireCode(t, e, "service_reconciliation_required")
	_, e = s.Accept(ctx, 0, send("forbidden"))
	requireCode(t, e, "service_reconciliation_required")
	requireCode(t, s.Healthy(ctx), "service_reconciliation_required")
	requireCode(t, s.Seal(ctx), "service_reconciliation_required")
	s.Close()
	maintainOK(t, c, "reconcile", "")
	next := openOK(t, c)
	value, e := next.Welcome(ctx, 0, nil)
	if e != nil || value.Welcome != "aaff" {
		t.Fatal("committed candidate lost", e)
	}
	sealClose(t, next)
}

func TestReconciliationCancellationAndConcurrentExactRetries(t *testing.T) {
	ctx := context.Background()
	s, _ := evidenceStore(t)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, e = s.Page(short, 1, m.Poll{After: "0", Limit: 4})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("read bypassed active transaction", e)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			ack, e := s.Accept(ctx, 0, send("concurrent"))
			if e == nil && ack.Sequence != "1" {
				e = m.Fail("duplicate_acceptance")
			}
			errors <- e
		})
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		if e != nil {
			t.Fatal(e)
		}
	}
	sealClose(t, s)
}

type heldCommittedTransaction struct {
	pgx.Tx
	committed, release chan struct{}
}

func (tx heldCommittedTransaction) Commit(ctx context.Context) error {
	if e := tx.Tx.Commit(ctx); e != nil {
		return e
	}
	close(tx.committed)
	<-tx.release
	return nil
}

func TestReconciliationReadersCannotObserveUnconfirmedDatabase(t *testing.T) {
	ctx := context.Background()
	s, _ := evidenceStore(t)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "UPDATE alpha_conversation SET welcome='aaff'"); e != nil {
		t.Fatal(e)
	}
	w := tx.(*evidencedTransaction)
	committed, release := make(chan struct{}), make(chan struct{})
	w.Tx = heldCommittedTransaction{w.Tx, committed, release}
	done := make(chan error, 1)
	go func() { done <- tx.Commit(ctx) }()
	<-committed
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	_, e = s.Welcome(short, 0, nil)
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) {
		close(release)
		<-done
		t.Fatal("unconfirmed write visible", e)
	}
	short, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
	_, e = s.Session(short, 0)
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) {
		close(release)
		<-done
		t.Fatal("read bypassed evidence completion", e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	value, e := s.Welcome(ctx, 0, nil)
	if e != nil || value.Welcome != "aaff" {
		t.Fatal("confirmed write unavailable", e)
	}
	sealClose(t, s)
}

func TestReconciliationMissingCorruptAndCopiedEvidence(t *testing.T) {
	ctx := context.Background()
	s, c := evidenceStore(t)
	s.Close()
	original, e := os.ReadFile(c.RecoveryState)
	if e != nil {
		t.Fatal(e)
	}
	for _, variant := range []string{"missing", "truncated", "run", "operation", "digest"} {
		t.Run(variant, func(t *testing.T) {
			if variant == "missing" {
				e = os.Remove(c.RecoveryState)
			} else {
				data := original
				if variant == "truncated" {
					data = data[:len(data)/2]
				} else {
					var st maintenanceState
					if e := json.Unmarshal(original, &st); e != nil {
						t.Fatal(e)
					}
					id, err := randomCheckpoint()
					if err != nil {
						t.Fatal(err)
					}
					switch variant {
					case "run":
						st.Evidence.RunID = id
					case "operation":
						st.Evidence.OperationID = id
					case "digest":
						st.Digest = id
					}
					data, e = json.Marshal(st)
				}
				if e == nil {
					e = os.WriteFile(c.RecoveryState, data, 0600)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e := Maintain(ctx, c, "reconcile", ""); e == nil {
				t.Fatal("corrupt evidence accepted")
			}
			if e := os.WriteFile(c.RecoveryState, original, 0600); e != nil {
				t.Fatal(e)
			}
		})
	}
	copyConfig := c
	copyConfig.RecoveryState += ".copy"
	if e = os.WriteFile(copyConfig.RecoveryState, original, 0600); e != nil {
		t.Fatal(e)
	}
	_, e = Maintain(ctx, copyConfig, "reconcile", "")
	requireCode(t, e, "maintenance_configuration_mismatch")
	maintainOK(t, c, "reconcile", "")
}
