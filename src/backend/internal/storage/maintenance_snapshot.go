package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
)

const ServiceVersion = "0.1.0-alpha.7"
const maintenanceVersion = "service-backup-alpha1"

// 顺序同时满足外键导入依赖；表名与排序列来自此封闭清单，不接受外部SQL。
var maintenanceTables = []struct{ Name, Order string }{
	{"schema_version", "version"}, {"alpha_conversation", "singleton"}, {"alpha_devices", "device_index"},
	{"business_configuration", "singleton"}, {"business_users", "principal,external_user"},
	{"device_identities", "device_index"}, {"device_credentials", "credential_id"},
	{"business_requests", "principal,request_id"}, {"alpha_messages", "accepted"},
	{"alpha_mailbox", "device_index,sequence"}, {"alpha_recovery", "ordinal"}, {"service_maintenance", "singleton"},
}

type tableSnapshot struct {
	Name string            `json:"name"`
	Rows []json.RawMessage `json:"rows"`
}
type databaseSnapshot struct {
	Structure string          `json:"structure"`
	Tables    []tableSnapshot `json:"tables"`
}
type serviceBackup struct {
	Version        string           `json:"version"`
	ServiceVersion string           `json:"service_version"`
	GuardID        string           `json:"guard_id"`
	Checkpoint     string           `json:"checkpoint"`
	Configuration  string           `json:"configuration"`
	Digest         string           `json:"digest"`
	Snapshot       databaseSnapshot `json:"snapshot"`
}

func digestJSON(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func snapshot(ctx context.Context, tx pgx.Tx) (databaseSnapshot, error) {
	return snapshotWithLimit(ctx, tx, backupRowsLimit)
}

// 完整接受/信箱原件可能超过64MiB备份文件预算；证据核对不能把备份预算
// 变成新的消息上限。256MiB覆盖现有256消息、4096业务请求及16恢复轮的有界状态。
func evidenceSnapshot(ctx context.Context, tx pgx.Tx) (databaseSnapshot, error) {
	return snapshotWithLimit(ctx, tx, evidenceLimit)
}

func snapshotWithLimit(ctx context.Context, tx pgx.Tx, limit int) (databaseSnapshot, error) {
	out := databaseSnapshot{}
	var version, count int
	if e := tx.QueryRow(ctx, "SELECT count(*),coalesce(max(version),0) FROM schema_version").Scan(&count, &version); e != nil {
		return out, e
	}
	if count != 1 || (version != 4 && version != 5 && version != 6) {
		return out, m.Fail("schema_version_unsupported")
	}
	// 结构完整参与比较；拒绝未纳入数据备份的表、视图、序列和自定义函数。
	var names []string
	if e := tx.QueryRow(ctx, `SELECT coalesce(array_agg(relname::text ORDER BY relname),'{}') FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN ('r','v','m','S','f','p')`).Scan(&names); e != nil {
		return out, e
	}
	want := map[string]bool{}
	for _, table := range maintenanceTables {
		want[table.Name] = true
	}
	if len(names) != len(want) {
		return out, m.Fail("maintenance_schema_mismatch")
	}
	for _, name := range names {
		if !want[name] {
			return out, m.Fail("maintenance_schema_mismatch")
		}
	}
	var functions int
	if e := tx.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE pronamespace=current_schema()::regnamespace`).Scan(&functions); e != nil {
		return out, e
	}
	if functions != 0 {
		return out, m.Fail("maintenance_schema_mismatch")
	}
	var structure string
	if e := tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(v ORDER BY v::text),'[]')::text FROM (
 SELECT jsonb_build_array('column',c.relname,a.attname,a.attnum,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid)) v
 FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE c.relnamespace=current_schema()::regnamespace AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT jsonb_build_array('constraint',c.relname,k.conname,pg_get_constraintdef(k.oid)) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace=current_schema()::regnamespace
 UNION ALL SELECT jsonb_build_array('index',tablename,indexname,replace(indexdef,quote_ident(current_schema())||'.','')) FROM pg_indexes WHERE schemaname=current_schema()
 UNION ALL SELECT jsonb_build_array('trigger',c.relname,t.tgname,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace=current_schema()::regnamespace AND NOT t.tgisinternal
 ) q`).Scan(&structure); e != nil {
		return out, e
	}
	out.Structure = digestJSON(json.RawMessage(structure))
	size := 0
	for _, table := range maintenanceTables {
		rows, e := tx.Query(ctx, "SELECT "+maintenanceRowJSON+" FROM "+pgx.Identifier{table.Name}.Sanitize()+" t ORDER BY "+table.Order)
		if e != nil {
			return out, e
		}
		item := tableSnapshot{Name: table.Name, Rows: []json.RawMessage{}}
		for rows.Next() {
			var raw string
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return out, e
			}
			size += len(raw)
			if size > limit {
				rows.Close()
				return out, m.Fail("maintenance_size_limit")
			}
			item.Rows = append(item.Rows, json.RawMessage(raw))
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		out.Tables = append(out.Tables, item)
	}
	return out, nil
}

func (s *Store) readSnapshot(ctx context.Context) (databaseSnapshot, error) {
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return databaseSnapshot{}, e
	}
	defer tx.Rollback(ctx)
	read := snapshot
	if s.maintenance != nil && s.maintenance.state.Evidence != nil {
		read = evidenceSnapshot
	}
	out, e := read(ctx, tx)
	if e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
