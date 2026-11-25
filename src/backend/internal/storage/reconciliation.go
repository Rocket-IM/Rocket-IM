package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
)

const reconciliationVersion = "service-reconcile-alpha1"
const reconciliationBackupVersion = "service-backup-alpha2"

// 每次持久替换保留最后完成态与至多一个候选；不保存秘密或从DB重建外部记录。
type reconciliationEvidence struct {
	RunID       string                 `json:"run_id"`
	OperationID string                 `json:"operation_id"`
	Pending     *reconciliationPending `json:"pending,omitempty"`
}
type reconciliationPending struct {
	RunID       string `json:"run_id"`
	OperationID string `json:"operation_id"`
	Digest      string `json:"digest"`
}

func (s *Store) checkEvidenceIdentity(data databaseSnapshot, st maintenanceState) error {
	if st.Evidence == nil {
		return nil
	}
	run, operation := st.Evidence.RunID, st.Evidence.OperationID
	if p := st.Evidence.Pending; p != nil {
		run, operation = p.RunID, p.OperationID
	}
	rows := data.Tables[len(data.Tables)-1].Rows
	var row struct {
		GuardID     string `json:"guard_id"`
		Path        string `json:"external_path"`
		RunID       string `json:"run_id"`
		OperationID string `json:"operation_id"`
	}
	if len(rows) != 1 || json.Unmarshal(rows[0], &row) != nil || row.GuardID != st.GuardID || row.Path != s.maintenance.path || row.RunID != run || row.OperationID != operation {
		return m.Fail("service_reconciliation_mismatch")
	}
	return nil
}

func validEvidence(st maintenanceState) bool {
	e := st.Evidence
	if st.Version == maintenanceVersion {
		return e == nil && st.Phase != "upgrading"
	}
	if st.Version != reconciliationVersion || e == nil || !m.Hex(e.RunID, 32, 32) {
		return false
	}
	if !m.Hex(e.OperationID, 32, 32) && !(st.Phase == "upgrading" && e.OperationID == "") {
		return false
	}
	if p := e.Pending; p != nil {
		if (st.Phase != "running" && st.Phase != "upgrading") || !m.Hex(p.RunID, 32, 32) || !m.Hex(p.OperationID, 32, 32) || !m.Hex(p.Digest, 32, 32) || p.OperationID == e.OperationID || p.Digest == st.Digest {
			return false
		}
	} else if st.Phase == "upgrading" {
		return false
	}
	return true
}

// 替换前也核对幸存原件；运行中丢失/改动记录不能被下一次写入隐式重建。
func (g *maintenanceGuard) replaceState(st maintenanceState) error {
	var prior maintenanceState
	if e := readPrivate(g.path, 65536, &prior); e != nil {
		return e
	}
	if digestJSON(prior) != digestJSON(g.state) {
		return m.Fail("service_reconciliation_required")
	}
	if e := writePrivate(g.path, st, true); e != nil {
		return e
	}
	g.state = st
	return nil
}

// reserveEvidence必须在原业务事务内调用；成功返回才允许提交PG。
func (s *Store) reserveEvidence(ctx context.Context, tx pgx.Tx, st maintenanceState, run string) error {
	id, e := randomCheckpoint()
	if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, "UPDATE service_maintenance SET run_id=$1,operation_id=$2 WHERE singleton AND guard_id=$3 AND external_path=$4", run, id, st.GuardID, s.maintenance.path)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return m.Fail("maintenance_configuration_mismatch")
	}
	data, e := evidenceSnapshot(ctx, tx)
	if e != nil {
		return e
	}
	evidence := *st.Evidence
	evidence.Pending = &reconciliationPending{RunID: run, OperationID: id, Digest: digestJSON(data)}
	st.Evidence = &evidence
	return s.maintenance.replaceState(st)
}

func (g *maintenanceGuard) completeEvidence(phase string) error {
	st := g.state
	p := st.Evidence.Pending
	if p == nil {
		return m.Fail("service_reconciliation_required")
	}
	st.Digest = p.Digest
	st.Evidence = &reconciliationEvidence{RunID: p.RunID, OperationID: p.OperationID}
	st.Phase = phase
	if phase == "sealed" {
		checkpoint, e := randomCheckpoint()
		if e != nil {
			return e
		}
		st.Checkpoint = checkpoint
	}
	return g.replaceState(st)
}

func (s *Store) enableReconciliation(ctx context.Context) error {
	g := s.maintenance
	if _, e := s.verifySealed(ctx); e != nil {
		return e
	}
	if g.state.Version == reconciliationVersion {
		return nil
	}
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, s.queries["migration_lock"]); e != nil {
		return e
	}
	data, e := snapshot(ctx, tx)
	if e != nil {
		return e
	}
	if digestJSON(data) != g.state.Digest {
		return m.Fail("service_backup_stale")
	}
	if e = applyMigration(ctx, tx, "005_service_reconciliation.sql"); e != nil {
		return e
	}
	run, e := randomCheckpoint()
	if e != nil {
		return e
	}
	st := g.state
	st.Version, st.Phase = reconciliationVersion, "upgrading"
	st.Evidence = &reconciliationEvidence{RunID: run}
	if e = s.reserveEvidence(ctx, tx, st, run); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return m.Fail("service_reconciliation_required")
	}
	return g.completeEvidence("sealed")
}

// 离线核对只认可幸存记录指向的完整状态；前态不能证明候选从未提交。
func (s *Store) reconcile(ctx context.Context) error {
	g := s.maintenance
	if g.state.Version != reconciliationVersion {
		return m.Fail("service_reconciliation_evidence_missing")
	}
	if g.state.Phase == "sealed" {
		_, e := s.verifySealed(ctx)
		return e
	}
	if g.state.Phase != "running" && g.state.Phase != "upgrading" {
		return m.Fail("service_reconciliation_required")
	}
	if g.target != g.state.Target {
		return m.Fail("maintenance_target_mismatch")
	}
	data, e := s.readSnapshot(ctx)
	if e != nil {
		return e
	}
	digest := digestJSON(data)
	if pending := g.state.Evidence.Pending; pending != nil {
		if digest != pending.Digest {
			return m.Fail("service_reconciliation_incomplete")
		}
		if e = s.checkEvidenceIdentity(data, g.state); e != nil {
			return e
		}
		return g.completeEvidence("sealed")
	}
	if digest != g.state.Digest {
		return m.Fail("service_reconciliation_mismatch")
	}
	if e = s.checkEvidenceIdentity(data, g.state); e != nil {
		return e
	}
	return s.sealEvidence(data)
}

func (s *Store) startEvidence(ctx context.Context) error {
	g := s.maintenance
	run, e := randomCheckpoint()
	if e != nil {
		return e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	st := g.state
	st.Phase = "running"
	if e = s.reserveEvidence(ctx, tx, st, run); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return m.Fail("service_reconciliation_required")
	}
	return g.completeEvidence("running")
}

func (s *Store) sealEvidence(data databaseSnapshot) error {
	g := s.maintenance
	if g.blocked || g.state.Evidence.Pending != nil || digestJSON(data) != g.state.Digest {
		return m.Fail("service_reconciliation_required")
	}
	checkpoint, e := randomCheckpoint()
	if e != nil {
		return e
	}
	st := g.state
	st.Phase, st.Checkpoint = "sealed", checkpoint
	return g.replaceState(st)
}
