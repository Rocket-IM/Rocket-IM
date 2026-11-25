package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
)

func (s *Store) exportService(ctx context.Context, path string) error {
	data, e := s.verifySealed(ctx)
	if e != nil {
		return e
	}
	return writePrivate(path, makeServiceBackup(data, s.maintenance.state), false)
}

func makeServiceBackup(data databaseSnapshot, st maintenanceState) serviceBackup {
	backup := serviceBackup{Version: maintenanceVersion, ServiceVersion: ServiceVersion, GuardID: st.GuardID, Checkpoint: st.Checkpoint, Configuration: st.Configuration, Digest: st.Digest, Snapshot: data}
	if st.Evidence != nil {
		backup.Version = reconciliationBackupVersion
	}
	return backup
}

func (s *Store) restoreService(ctx context.Context, path string) error {
	g := s.maintenance
	st := g.state
	if st.Phase != "sealed" && st.Phase != "restoring" {
		return m.Fail("service_reconciliation_required")
	}
	var backup serviceBackup
	if e := readPrivate(path, backupLimit, &backup); e != nil {
		return e
	}
	wantVersion := maintenanceVersion
	if st.Evidence != nil {
		wantVersion = reconciliationBackupVersion
	}
	if backup.Version != wantVersion || (backup.ServiceVersion != ServiceVersion && backup.ServiceVersion != "0.1.0-alpha.6" && backup.ServiceVersion != "0.1.0-alpha.5" && !(st.Evidence == nil && backup.ServiceVersion == "0.1.0-alpha.4")) {
		return m.Fail("service_backup_version_unsupported")
	}
	if backup.GuardID != st.GuardID || backup.Configuration != st.Configuration {
		return m.Fail("maintenance_configuration_mismatch")
	}
	if backup.Checkpoint != st.Checkpoint || backup.Digest != st.Digest {
		return m.Fail("service_backup_stale")
	}
	if digestJSON(backup.Snapshot) != st.Digest || len(backup.Snapshot.Tables) != len(maintenanceTables) {
		return m.Fail("service_backup_invalid")
	}
	for i, table := range maintenanceTables {
		if backup.Snapshot.Tables[i].Name != table.Name {
			return m.Fail("service_backup_invalid")
		}
	}
	if st.Phase == "restoring" && st.PendingTarget != g.target {
		return m.Fail("maintenance_target_mismatch")
	}
	// 只接受空目标、同一预约目标的全事务结果，或已经完成的同一恢复。
	if g.target != st.Target {
		var elsewhere int
		if e := g.conn.QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname!='information_schema' AND n.nspname!=current_schema() AND c.relkind IN ('r','v','m','S','f','p')`).Scan(&elsewhere); e != nil {
			return e
		}
		if elsewhere != 0 {
			return m.Fail("maintenance_target_not_empty")
		}
	}
	var objects int
	if e := g.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace) + (SELECT count(*) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace)`).Scan(&objects); e != nil {
		return e
	}
	if objects != 0 {
		if st.Phase != "restoring" && st.Target != g.target {
			return m.Fail("maintenance_target_not_empty")
		}
		if st.Phase != "restoring" && st.RestoredCheckpoint != st.Checkpoint {
			return m.Fail("maintenance_target_not_new")
		}
		data, e := s.readSnapshot(ctx)
		if e != nil {
			return e
		}
		if digestJSON(data) != st.Digest {
			return m.Fail("maintenance_target_mismatch")
		}
	} else {
		if g.target == st.Target {
			return m.Fail("maintenance_target_not_new")
		}
		st.Phase = "restoring"
		st.PendingTarget = g.target
		if e := writePrivate(g.path, st, true); e != nil {
			return e
		}
		g.state = st
		if e := s.importSnapshot(ctx, backup.Snapshot, st.Digest); e != nil {
			return e
		}
	}
	st.Phase = "sealed"
	st.Target = g.target
	st.PendingTarget = ""
	st.RestoredCheckpoint = st.Checkpoint
	if e := writePrivate(g.path, st, true); e != nil {
		return e
	}
	g.state = st
	return nil
}

func (s *Store) importSnapshot(ctx context.Context, data databaseSnapshot, digest string) error {
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, s.queries["migration_lock"]); e != nil {
		return e
	}
	for _, name := range []string{"001_alpha.sql", "002_business_identity.sql", "003_successor_recovery.sql", "004_service_recovery.sql"} {
		if e = applyMigration(ctx, tx, name); e != nil {
			return e
		}
	}
	var versions []struct {
		Version int `json:"version"`
	}
	rawVersions, e := json.Marshal(data.Tables[0].Rows)
	if e != nil || json.Unmarshal(rawVersions, &versions) != nil || len(versions) != 1 {
		return m.Fail("service_backup_invalid")
	}
	if versions[0].Version >= 5 {
		if e = applyMigration(ctx, tx, "005_service_reconciliation.sql"); e != nil {
			return e
		}
	}
	if versions[0].Version == 6 {
		if e = applyMigration(ctx, tx, "006_known_capacity.sql"); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, "DELETE FROM schema_version"); e != nil {
		return e
	}
	for _, table := range data.Tables {
		raw, e := json.Marshal(table.Rows)
		if e != nil {
			return m.Fail("service_backup_invalid")
		}
		name := pgx.Identifier{table.Name}.Sanitize()
		if _, e = tx.Exec(ctx, "INSERT INTO "+name+" SELECT * FROM jsonb_populate_recordset(NULL::"+name+",$1::jsonb)", string(raw)); e != nil {
			return e
		}
	}
	imported, e := snapshot(ctx, tx)
	if e != nil {
		return e
	}
	if digestJSON(imported) != digest {
		return m.Fail("service_backup_invalid")
	}
	return tx.Commit(ctx)
}
