package storage

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// 原生产限额的单一来源。诊断不降低准入，也不建立预留。
const messageLimit = 256
const businessRequestLimit = 4096
const recoveryRoundLimit = 16
const recoveryJSONLimit = 28 * 1024 * 1024
const evidenceLimit = 256 * 1024 * 1024
const backupRowsLimit = backupLimit - 65536
const maintenanceRowJSON = "to_jsonb(t)::text"

func (s *Store) businessUsage(ctx context.Context, tx pgx.Tx) (int64, error) {
	var count int64
	e := tx.QueryRow(ctx, s.queries["business_count"]).Scan(&count)
	return count, e
}
func (s *Store) recoveryUsage(ctx context.Context, tx pgx.Tx) (int64, int64, error) {
	var count, size int64
	e := tx.QueryRow(ctx, s.queries["recovery_count"]).Scan(&count, &size)
	return count, size, e
}
func snapshotRowBytes(ctx context.Context, tx pgx.Tx) (int64, error) {
	var total int64
	for _, table := range maintenanceTables {
		var size int64
		if e := tx.QueryRow(ctx, "SELECT COALESCE(SUM(octet_length("+maintenanceRowJSON+")),0) FROM "+pgx.Identifier{table.Name}.Sanitize()+" t").Scan(&size); e != nil {
			return 0, e
		}
		total += size
	}
	return total, nil
}
