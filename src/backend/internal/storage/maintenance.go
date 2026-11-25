package storage

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"time"
)

type maintenanceState struct {
	Version            string                  `json:"version"`
	GuardID            string                  `json:"guard_id"`
	Checkpoint         string                  `json:"checkpoint"`
	Configuration      string                  `json:"configuration"`
	Phase              string                  `json:"phase"`
	Target             string                  `json:"target"`
	PendingTarget      string                  `json:"pending_target,omitempty"`
	RestoredCheckpoint string                  `json:"restored_checkpoint,omitempty"`
	Digest             string                  `json:"digest"`
	Evidence           *reconciliationEvidence `json:"evidence,omitempty"`
}
type maintenanceGuard struct {
	file                        *os.File
	conn                        *pgxpool.Conn
	path, target, configuration string
	state                       maintenanceState
	blocked                     bool
}

func (g *maintenanceGuard) close() {
	if g.conn != nil {
		// 直接关闭租用连接，确保session advisory lock绝不回到连接池。
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = g.conn.Conn().Close(ctx)
		cancel()
		g.conn.Release()
	}
	if g.file != nil {
		_ = g.file.Close()
	}
}
func randomCheckpoint() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", m.Fail("maintenance_random_failed")
	}
	return hex.EncodeToString(b), nil
}
func configurationDigest(c config.Config) (string, error) {
	pair, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if e != nil {
		return "", m.Fail("maintenance_secrets_unavailable")
	}
	key := ""
	if c.Business != nil {
		key = digestJSON(c.Business.CredentialKey)
	}
	return digestJSON(struct {
		Binding, RecoveryPath string
		Business              *config.Business
		Key                   string
		Certificate           [][]byte
	}{c.Binding(), c.RecoveryState, c.Business, key, pair.Certificate}), nil
}
func (s *Store) acquireMaintenance(ctx context.Context, fresh bool) error {
	if s.Config.RecoveryState == "" {
		return m.Fail("service_maintenance_required")
	}
	g := &maintenanceGuard{path: s.Config.RecoveryState}
	var e error
	g.file, e = lockMaintenance(g.path)
	if e != nil {
		return e
	}
	s.maintenance = g
	if g.configuration, e = configurationDigest(s.Config); e != nil {
		return e
	}
	g.conn, e = s.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	var system, database, schema string
	var dbOID, schemaOID uint32
	// 维护角色须能读取本机集群标识；仅hash目标定位信息，不记录DSN/口令。
	if e = g.conn.QueryRow(ctx, `SELECT system_identifier::text,current_database(),current_schema(),
 (SELECT oid FROM pg_database WHERE datname=current_database()),current_schema()::regnamespace::oid FROM pg_control_system()`).Scan(&system, &database, &schema, &dbOID, &schemaOID); e != nil {
		return m.Fail("maintenance_target_unavailable")
	}
	var locked bool
	if e = g.conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(1380536370,$1)", int32(schemaOID)).Scan(&locked); e != nil || !locked {
		return m.Fail("service_maintenance_busy")
	}
	connection := g.conn.Conn().Config()
	g.target = digestJSON(struct {
		System, Host, Database, Schema string
		Port                           uint16
		DatabaseOID, SchemaOID         uint32
	}{system, connection.Host, database, schema, connection.Port, dbOID, schemaOID})
	if fresh {
		if _, e = os.Lstat(g.path); !os.IsNotExist(e) {
			return m.Fail("maintenance_state_exists")
		}
		return nil
	}
	if e = readPrivate(g.path, 65536, &g.state); e != nil {
		return e
	}
	st := g.state
	if st.Phase == "enrolling" {
		return m.Fail("service_reconciliation_required")
	}
	if !validEvidence(st) || !m.Hex(st.GuardID, 32, 32) || !m.Hex(st.Checkpoint, 32, 32) || !m.Hex(st.Target, 32, 32) || !m.Hex(st.Digest, 32, 32) {
		return m.Fail("maintenance_state_invalid")
	}
	if (st.Phase != "sealed" && st.Phase != "running" && st.Phase != "restoring" && st.Phase != "upgrading") ||
		(st.Phase == "restoring" && !m.Hex(st.PendingTarget, 32, 32)) || (st.Phase != "restoring" && st.PendingTarget != "") {
		return m.Fail("maintenance_state_invalid")
	}
	if st.RestoredCheckpoint != "" && !m.Hex(st.RestoredCheckpoint, 32, 32) {
		return m.Fail("maintenance_state_invalid")
	}
	if st.Configuration != g.configuration {
		return m.Fail("maintenance_configuration_mismatch")
	}
	return nil
}
func (s *Store) verifySealed(ctx context.Context) (databaseSnapshot, error) {
	g := s.maintenance
	if g.state.Phase != "sealed" {
		return databaseSnapshot{}, m.Fail("service_reconciliation_required")
	}
	if g.state.Target != g.target {
		return databaseSnapshot{}, m.Fail("maintenance_target_mismatch")
	}
	data, e := s.readSnapshot(ctx)
	if e != nil {
		return data, e
	}
	if digestJSON(data) != g.state.Digest {
		return data, m.Fail("service_backup_stale")
	}
	if e = s.checkEvidenceIdentity(data, g.state); e != nil {
		return data, e
	}
	return data, nil
}
func (s *Store) startGuarded(ctx context.Context) error {
	if e := s.acquireMaintenance(ctx, false); e != nil {
		return e
	}
	if _, e := s.verifySealed(ctx); e != nil {
		return e
	}
	g := s.maintenance
	if g.state.Evidence != nil {
		if e := s.startEvidence(ctx); e != nil {
			return e
		}
		s.evidenced = true
		return nil
	}
	g.state.Phase = "running"
	return writePrivate(g.path, g.state, true)
}

// Seal 仅由停止接入并排空所有HTTP/WSS任务的装配层调用；Close本身永不解除门禁。
func (s *Store) Seal(ctx context.Context) error {
	g := s.maintenance
	if g == nil {
		return nil
	}
	if g.state.Phase != "running" {
		return m.Fail("service_reconciliation_required")
	}
	data, e := s.readSnapshot(ctx)
	if e != nil {
		return e
	}
	if g.state.Evidence != nil {
		return s.sealEvidence(data)
	}
	checkpoint, e := randomCheckpoint()
	if e != nil {
		return e
	}
	st := g.state
	st.Phase = "sealed"
	st.Checkpoint = checkpoint
	st.Digest = digestJSON(data)
	if e = writePrivate(g.path, st, true); e != nil {
		return e
	}
	g.state = st
	return nil
}

type MaintenanceResult struct {
	Version    string `json:"version"`
	Operation  string `json:"operation"`
	Checkpoint string `json:"checkpoint"`
	Digest     string `json:"digest"`
	Status     string `json:"status"`
}

// Maintain 是离线维护入口；正常操作没有测试钩子，不接收SQL或用户秘密恢复材料。
func Maintain(ctx context.Context, c config.Config, operation, backupPath string) (MaintenanceResult, error) {
	result := MaintenanceResult{Version: maintenanceVersion, Operation: operation}
	if operation != "enroll" && operation != "backup" && operation != "restore" && operation != "enable-reconciliation" && operation != "reconcile" && operation != "enable-capacity-reserve" && operation != "enable-capacity-workset" {
		return result, m.Fail("maintenance_operation_invalid")
	}
	s, e := connect(ctx, c)
	if e != nil {
		return result, e
	}
	defer s.Close()
	if e = s.acquireMaintenance(ctx, operation == "enroll"); e != nil {
		return result, e
	}
	switch operation {
	case "enroll":
		e = s.enroll(ctx)
	case "backup":
		e = s.exportService(ctx, backupPath)
	case "restore":
		e = s.restoreService(ctx, backupPath)
	case "enable-reconciliation":
		e = s.enableReconciliation(ctx)
	case "enable-capacity-reserve":
		e = s.enableCapacityReserve(ctx)
	case "enable-capacity-workset":
		e = s.enableCapacityWorkset(ctx)
	case "reconcile":
		e = s.reconcile(ctx)
	}
	if e != nil {
		return result, e
	}
	result.Checkpoint = s.maintenance.state.Checkpoint
	result.Version = s.maintenance.state.Version
	result.Digest = s.maintenance.state.Digest
	result.Status = "complete"
	return result, nil
}

func (s *Store) enroll(ctx context.Context) error {
	g := s.maintenance
	id, e := randomCheckpoint()
	if e != nil {
		return e
	}
	g.state = maintenanceState{Version: maintenanceVersion, GuardID: id, Configuration: g.configuration, Target: g.target, Phase: "enrolling"}
	// 首先确认原库不曾登记；缺少幸存维护记录不能靠enroll重建信任。
	var exists bool
	if e = g.conn.QueryRow(ctx, "SELECT to_regclass('service_maintenance') IS NOT NULL").Scan(&exists); e != nil {
		return e
	}
	if exists {
		var count int
		if e = g.conn.QueryRow(ctx, "SELECT count(*) FROM service_maintenance").Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return m.Fail("service_maintenance_required")
		}
	}
	if e = writePrivate(g.path, g.state, false); e != nil {
		return e
	}
	if e = s.migrate(ctx); e != nil {
		return e
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "INSERT INTO service_maintenance(singleton,guard_id,external_path) VALUES(true,$1,$2)", id, g.path); e != nil {
		return e
	}
	data, e := snapshot(ctx, tx)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	g.state.Checkpoint = id
	g.state.Digest = digestJSON(data)
	g.state.Phase = "sealed"
	return writePrivate(g.path, g.state, true)
}
