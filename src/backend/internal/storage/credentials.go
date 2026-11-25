package storage

import (
	"context"
	"github.com/jackc/pgx/v5"
	"rocket-im/service/internal/auth"
	m "rocket-im/service/internal/messaging"
	"time"
)

type credential struct {
	Principal, ExternalUser, Account, Device string
	ExpiresAt                                time.Time
	Revoked                                  bool
}

func (s *Store) credential(ctx context.Context, tx pgx.Tx, id string) (credential, error) {
	var c credential
	e := tx.QueryRow(ctx, s.queries["credential_lookup"], id).Scan(&c.Principal, &c.ExternalUser, &c.Account, &c.Device, &c.ExpiresAt, &c.Revoked)
	return c, e
}
func (s *Store) validCredential(ctx context.Context, tx pgx.Tx, id string, now time.Time) (credential, error) {
	c, e := s.credential(ctx, tx, id)
	if e == pgx.ErrNoRows {
		return c, m.Fail("unauthorized")
	}
	if e != nil {
		return c, e
	}
	if c.Revoked {
		return c, m.Fail("credential_revoked")
	}
	if !now.Before(c.ExpiresAt) {
		return c, m.Fail("credential_expired")
	}
	if _, ok := s.Config.BusinessPrincipal(c.Principal, now); !ok {
		return c, m.Fail("unauthorized")
	}
	return c, nil
}
func (s *Store) AuthenticateDevice(ctx context.Context, token string) (int, time.Time, error) {
	if s.Config.Business == nil {
		if e := s.Healthy(ctx); e != nil {
			return 0, time.Time{}, e
		}
		if i, ok := s.Config.Authenticate(token); ok {
			return i, time.Time{}, nil
		}
		return 0, time.Time{}, m.Fail("unauthorized")
	}
	id, ok := auth.Verify(s.Config.Business.CredentialKey, s.Config.Service, token)
	if !ok {
		return 0, time.Time{}, m.Fail("unauthorized")
	}
	tx, e := s.beginRead(ctx)
	if e != nil {
		return 0, time.Time{}, e
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	c, e := s.validCredential(ctx, tx, id, now)
	if e != nil {
		return 0, time.Time{}, e
	}
	var index int
	e = tx.QueryRow(ctx, s.queries["credential_device"], c.Account, c.Device, c.Principal, c.ExternalUser).Scan(&index)
	if e != nil {
		return 0, time.Time{}, e
	}
	p, _ := s.Config.BusinessPrincipal(c.Principal, now)
	deadline := c.ExpiresAt
	if p.ExpiresAt.Before(deadline) {
		deadline = p.ExpiresAt
	}
	return index, deadline, tx.Commit(ctx)
}
