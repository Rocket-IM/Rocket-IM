package storage

import (
	"context"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"strconv"
)

// 范围只到各设备下一个未知message前的连续已知控制事件；不承诺尚未解密的报告。
// PG的同一个to_jsonb表达式测量完整行的变更，没有假定Go紧凑JSON等于PG表示。
func (s *Store) knownReserve(ctx context.Context, tx pgx.Tx) (int64, int64, error) {
	var controls, growth int64
	e := tx.QueryRow(ctx, s.queries["capacity_known_controls"]).Scan(&controls, &growth)
	if e != nil {
		return 0, 0, e
	}
	var count, version int
	if e = tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&count, &version); e != nil {
		return 0, 0, e
	}
	if version >= 7 {
		additional, err := s.worksetGrowth(ctx, tx)
		if err != nil {
			return 0, 0, err
		}
		growth += additional
	}
	return controls, growth, e
}
func (s *Store) checkKnownReserve(ctx context.Context, tx pgx.Tx) error {
	var count, version int
	if e := tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&count, &version); e != nil {
		return e
	}
	if version < 6 || version > 8 {
		return nil
	}
	if count != 1 || !s.evidenced {
		return m.Fail("service_reconciliation_required")
	}
	_, growth, e := s.knownReserve(ctx, tx)
	if e != nil {
		return e
	}
	used, e := snapshotRowBytes(ctx, tx)
	if e != nil {
		return e
	}
	if used+growth > evidenceLimit {
		return m.Fail("capacity_reserved")
	}
	return nil
}
func (s *Store) capacityReservation(ctx context.Context, tx pgx.Tx, out *m.Capacity) error {
	out.Reserve = m.CapacityReserve{State: "not_enabled", Resources: []m.CapacityReservedResource{}, Work: []m.CapacityReservedWork{}}
	if out.Schema != "6" && out.Schema != "7" && out.Schema != "8" {
		return nil
	}
	controls, growth, e := s.knownReserve(ctx, tx)
	if e != nil {
		return e
	}
	used, e := snapshotRowBytes(ctx, tx)
	if e != nil {
		return e
	}
	if used+growth > evidenceLimit {
		return m.Fail("capacity_reserved")
	}
	out.Reserve.State = "bounded_ready"
	out.Reserve.Resources = []m.CapacityReservedResource{{Category: "reconciliation_row_bytes", ProtectedRemaining: strconv.FormatInt(growth, 10), OrdinaryAvailable: strconv.FormatInt(evidenceLimit-used-growth, 10)}}
	out.Reserve.Work = []m.CapacityReservedWork{{Kind: "known_control_report", Count: strconv.FormatInt(controls, 10)}}
	return nil
}

// 必须先封存并已启用原外部对账；升级也沿原候选证据/未知提交门禁，旧包拒载schema6。
func (s *Store) enableCapacityReserve(ctx context.Context) error {
	return s.enableCapacityVersion(ctx, 6, "006_known_capacity.sql")
}
func (s *Store) enableCapacityWorkset(ctx context.Context) error {
	return s.enableCapacityVersion(ctx, 7, "007_common_workset.sql")
}
func (s *Store) enableRepeatedWorkset(ctx context.Context) error {
	return s.enableCapacityVersion(ctx, 8, "008_repeated_workset.sql")
}
func (s *Store) enableCapacityVersion(ctx context.Context, want int, migration string) error {
	g := s.maintenance
	if _, e := s.verifySealed(ctx); e != nil {
		return e
	}
	if g.state.Evidence == nil {
		return m.Fail("service_reconciliation_evidence_missing")
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, s.queries["migration_lock"]); e != nil {
		return e
	}
	data, e := evidenceSnapshot(ctx, tx)
	if e != nil {
		return e
	}
	if digestJSON(data) != g.state.Digest {
		return m.Fail("service_backup_stale")
	}
	var count, version int
	if e = tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&count, &version); e != nil {
		return e
	}
	if count != 1 {
		return m.Fail("schema_version_unsupported")
	}
	if version >= want && version <= 8 {
		return nil
	}
	if version != want-1 {
		return m.Fail("schema_version_unsupported")
	}
	if e = applyMigration(ctx, tx, migration); e != nil {
		return e
	}
	// 只有本次受控升级的局部Store设定，运行态的evidenced仍在Open时固定。
	s.evidenced = true
	if e = s.checkKnownReserve(ctx, tx); e != nil {
		return e
	}
	st := g.state
	st.Phase = "upgrading"
	if e = s.reserveEvidence(ctx, tx, st, st.Evidence.RunID); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return m.Fail("service_reconciliation_required")
	}
	return g.completeEvidence("sealed")
}
