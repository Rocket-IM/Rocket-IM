package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/jackc/pgx/v5"
	"rocket-im/service/db"
	m "rocket-im/service/internal/messaging"
)

func applyMigration(ctx context.Context, tx pgx.Tx, name string) error {
	raw, e := db.Files.ReadFile("migrations/" + name)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, string(raw))
	return e
}
func (s *Store) seedIdentities(ctx context.Context, tx pgx.Tx) error {
	for i, d := range s.Config.Devices {
		if _, e := tx.Exec(ctx, s.queries["seed_identity"], i, d.Account, d.Device, d.IdentityKey); e != nil {
			return e
		}
		identity, e := s.identity(ctx, tx, i)
		if e != nil {
			return e
		}
		if identity != s.Config.Identity(i) {
			return m.Fail("configuration_mismatch")
		}
	}
	if s.Config.Business != nil {
		key := sha256.Sum256([]byte(s.Config.Business.CredentialKey))
		digest := hex.EncodeToString(key[:])
		if _, e := tx.Exec(ctx, s.queries["business_key_insert"], digest); e != nil {
			return e
		}
		var prior string
		if e := tx.QueryRow(ctx, s.queries["business_key"]).Scan(&prior); e != nil {
			return e
		}
		if prior != digest {
			return m.Fail("configuration_mismatch")
		}
	} else {
		var key string
		e := tx.QueryRow(ctx, s.queries["business_key"]).Scan(&key)
		if e == nil {
			return m.Fail("configuration_mismatch")
		}
		if e != pgx.ErrNoRows {
			return e
		}
	}
	return nil
}
func (s *Store) identity(ctx context.Context, tx pgx.Tx, index int) (m.Identity, error) {
	i := m.Identity{Scope: m.Scope{Service: s.Config.Service}}
	e := tx.QueryRow(ctx, s.queries["identity"], index).Scan(&i.Scope.Account, &i.Scope.Device, &i.IdentityKey)
	if e == pgx.ErrNoRows {
		return i, m.Fail("peer_not_ready")
	}
	return i, e
}
func (s *Store) Session(ctx context.Context, index int) (m.Session, error) {
	out := m.Session{Version: m.Version, Service: s.Config.Service, Conversation: s.Config.Conversation, Creator: index == 0}
	tx, e := s.beginRead(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if out.Own, e = s.identity(ctx, tx, index); e != nil {
		return out, e
	}
	if out.Peer, e = s.identity(ctx, tx, 1-index); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
