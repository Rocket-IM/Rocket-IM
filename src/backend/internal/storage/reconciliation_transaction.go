package storage

import (
	"context"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"time"
)

// 准入持续到PG提交及外部完成记录均持久成功。读请求也不能看到两者之间的状态。
type evidencedTransaction struct {
	pgx.Tx
	store    *Store
	writable bool
	released bool
}

func (s *Store) enter(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	select {
	case s.operations <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if e := ctx.Err(); e != nil {
		<-s.operations
		return e
	}
	g := s.maintenance
	if g.blocked || g.state.Phase != "running" || g.state.Evidence.Pending != nil {
		<-s.operations
		return m.Fail("service_reconciliation_required")
	}
	// 请求取消不能关闭持有维护锁的独立连接。连接检查有独立的短超时；
	// 检查后再尊重请求取消，此时尚未开始任何业务事务或外部预约。
	lockContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	e := g.conn.Conn().Ping(lockContext)
	cancel()
	if e != nil {
		g.blocked = true
		<-s.operations
		return m.Fail("service_reconciliation_required")
	}
	if e := ctx.Err(); e != nil {
		<-s.operations
		return e
	}
	return nil
}

func (s *Store) beginOperation(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	guarded := s.evidenced // Open发布Store前固定；运行中不读取可替换的证据指针。
	if guarded {
		if e := s.enter(ctx); e != nil {
			return nil, e
		}
	}
	tx, e := s.Pool.BeginTx(ctx, options)
	if e != nil {
		if guarded {
			<-s.operations
		}
		return nil, e
	}
	if !guarded {
		return tx, nil
	}
	wrapped := &evidencedTransaction{Tx: tx, store: s, writable: options.AccessMode != pgx.ReadOnly}
	if wrapped.writable {
		data, err := evidenceSnapshot(ctx, tx)
		if err == nil && digestJSON(data) != s.maintenance.state.Digest {
			err = m.Fail("service_reconciliation_mismatch")
		}
		if err != nil {
			// 这里尚未执行业务写入；取消只回滚当前事务，不制造结果未知。
			if ctx.Err() == nil {
				s.maintenance.blocked = true
			}
			_ = wrapped.Rollback(ctx)
			return nil, err
		}
	}
	return wrapped, nil
}

func (t *evidencedTransaction) release() {
	if !t.released {
		t.released = true
		<-t.store.operations
	}
}
func (t *evidencedTransaction) Rollback(ctx context.Context) error {
	if t.released {
		return pgx.ErrTxClosed
	}
	defer t.release()
	return t.Tx.Rollback(ctx)
}
func (t *evidencedTransaction) Commit(ctx context.Context) error {
	if t.released {
		return pgx.ErrTxClosed
	}
	defer t.release()
	defer t.Tx.Rollback(ctx)
	s, g := t.store, t.store.maintenance
	if t.writable {
		if e := s.checkKnownReserve(ctx, t.Tx); e != nil {
			return e
		}
		data, e := evidenceSnapshot(ctx, t.Tx)
		if e != nil {
			return e
		}
		if digestJSON(data) != g.state.Digest {
			// 一旦开始外部写入，任何错误都可能是结果未知；当前进程只允许关闭。
			g.blocked = true
			if e = s.reserveEvidence(ctx, t.Tx, g.state, g.state.Evidence.RunID); e != nil {
				return m.Fail("service_reconciliation_required")
			}
			if e = t.Tx.Commit(ctx); e != nil {
				return m.Fail("service_reconciliation_required")
			}
			if e = g.completeEvidence("running"); e != nil {
				return m.Fail("service_reconciliation_required")
			}
			g.blocked = false
			return nil
		}
	}
	return t.Tx.Commit(ctx)
}

func (s *Store) beginRead(ctx context.Context) (pgx.Tx, error) {
	return s.beginOperation(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
}

func (s *Store) Healthy(ctx context.Context) error {
	tx, e := s.beginRead(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	return tx.Commit(ctx)
}
