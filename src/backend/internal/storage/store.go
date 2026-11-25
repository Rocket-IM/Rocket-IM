// Package storage 由PostgreSQL事务持有接受顺序、设备信箱和幂等账本。
package storage

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"rocket-im/service/db"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"strings"
	"sync"
	"time"
)

type Store struct {
	Pool        *pgxpool.Pool
	Config      config.Config
	queries     map[string]string
	maintenance *maintenanceGuard
	closeOnce   sync.Once
	operations  chan struct{}
	evidenced   bool
}

func Open(ctx context.Context, c config.Config) (*Store, error) {
	s, e := connect(ctx, c)
	if e != nil {
		return nil, e
	}
	if c.RecoveryState != "" {
		e = s.startGuarded(ctx)
	} else {
		e = s.migrate(ctx)
	}
	if e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}

func connect(ctx context.Context, c config.Config) (*Store, error) {
	cfg, e := pgxpool.ParseConfig(c.DatabaseURL)
	if e != nil {
		return nil, errors.New("invalid_database_config")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 0
	cfg.ConnConfig.ConnectTimeout = 3 * time.Second
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, errors.New("database_connect_failed")
	}
	s := &Store{Pool: p, Config: c, queries: map[string]string{}, operations: make(chan struct{}, 1)}
	for _, file := range []string{"alpha.sql", "business.sql", "recovery.sql", "capacity.sql"} {
		raw, e := db.Files.ReadFile("queries/" + file)
		if e != nil {
			p.Close()
			return nil, e
		}
		for _, part := range strings.Split(string(raw), "-- name: ")[1:] {
			name, query, ok := strings.Cut(part, "\n")
			if !ok {
				p.Close()
				return nil, errors.New("query_missing")
			}
			s.queries[name] = strings.TrimSpace(query)
		}
	}
	return s, nil
}
func (s *Store) migrate(ctx context.Context) error {
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	// 所有DDL和配置绑定一起提交；并发启动不会互相覆盖。
	if _, e = tx.Exec(ctx, s.queries["migration_lock"]); e != nil {
		return e
	}
	var exists bool
	if e = tx.QueryRow(ctx, "SELECT to_regclass('schema_version') IS NOT NULL").Scan(&exists); e != nil {
		return e
	}
	if !exists {
		if e = applyMigration(ctx, tx, "001_alpha.sql"); e != nil {
			return e
		}
	}
	var version, versionCount int
	if e = tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&versionCount, &version); e != nil {
		return e
	}
	if versionCount == 1 && version == 5 {
		return m.Fail("service_maintenance_required")
	}
	if versionCount != 1 || version < 1 || version > 4 {
		return m.Fail("schema_version_unsupported")
	}
	if version == 4 {
		var registered bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM service_maintenance)").Scan(&registered); e != nil {
			return e
		}
		if registered {
			return m.Fail("service_maintenance_required")
		}
	}
	if _, e = tx.Exec(ctx, s.queries["insert_binding"], s.Config.Binding()); e != nil {
		return e
	}
	var binding string
	if e = tx.QueryRow(ctx, s.queries["binding"]).Scan(&binding); e != nil {
		return e
	}
	if binding != s.Config.Binding() {
		return m.Fail("configuration_mismatch")
	}
	if _, e = tx.Exec(ctx, s.queries["insert_devices"]); e != nil {
		return e
	}
	if version == 1 {
		if e = applyMigration(ctx, tx, "002_business_identity.sql"); e != nil {
			return e
		}
	}
	if version < 3 {
		if e = applyMigration(ctx, tx, "003_successor_recovery.sql"); e != nil {
			return e
		}
	}
	if version < 4 {
		if e = applyMigration(ctx, tx, "004_service_recovery.sql"); e != nil {
			return e
		}
	}
	if e = s.seedIdentities(ctx, tx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	tx, e := s.beginOperation(ctx, pgx.TxOptions{})
	if e != nil {
		return nil, e
	}
	// 固定单会话Alpha由唯一行锁串行分配全部事件序号。锁随提交释放，不用非事务序列。
	var accepted int64
	if e = tx.QueryRow(ctx, s.queries["lock"]).Scan(&accepted); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}
func (s *Store) Close() {
	s.closeOnce.Do(func() {
		if s.maintenance != nil {
			s.maintenance.close()
		}
		s.Pool.Close()
	})
}
