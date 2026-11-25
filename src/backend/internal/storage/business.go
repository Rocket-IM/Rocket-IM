package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"rocket-im/service/internal/auth"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/users"
	"time"
)

func randomID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

// Business 的授权、身份绑定、请求账本和签发记录共用事务；提交后才构造含令牌的响应。
func (s *Store) Business(ctx context.Context, principal config.Principal, op string, c users.Command) (users.Result, error) {
	var out users.Result
	if e := c.Validate(op, s.Config.Service); e != nil {
		return out, e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return out, e
	}
	sum := sha256.Sum256(append([]byte(op+"\x00"), raw...))
	digest := hex.EncodeToString(sum[:])
	tx, e := s.begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	// 等锁后重新检查有效期；过期请求不消耗请求号，也不产生身份或凭证。
	now := time.Now().UTC()
	current, ok := s.Config.BusinessPrincipal(principal.ID, now)
	if !ok {
		return out, m.Fail("unauthorized")
	}
	principal = current
	var prior string
	e = tx.QueryRow(ctx, s.queries["business_lookup"], principal.ID, c.RequestID).Scan(&prior, &raw)
	if e == nil {
		if prior != digest {
			return out, m.Fail("idempotency_conflict")
		}
		if e = json.Unmarshal(raw, &out); e != nil {
			return out, e
		}
		if op == "credentials" {
			if _, e = s.validCredential(ctx, tx, out.CredentialID, now); e != nil {
				return out, e
			}
		}
	} else if e == pgx.ErrNoRows {
		var count int
		if e = tx.QueryRow(ctx, s.queries["business_count"]).Scan(&count); e != nil {
			return out, e
		}
		if count >= 4096 {
			return out, m.Fail("request_limit")
		}
		if out, e = s.businessApply(ctx, tx, principal, op, c, now); e != nil {
			return out, e
		}
		raw, e = json.Marshal(out)
		if e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, s.queries["business_remember"], principal.ID, c.RequestID, digest, raw); e != nil {
			return out, e
		}
	} else {
		return out, e
	}
	if e = tx.Commit(ctx); e != nil {
		return users.Result{}, e
	}
	if op == "credentials" {
		out.Token = auth.Token(s.Config.Business.CredentialKey, s.Config.Service, out.CredentialID)
	}
	return out, nil
}
func (s *Store) businessApply(ctx context.Context, tx pgx.Tx, p config.Principal, op string, c users.Command, now time.Time) (users.Result, error) {
	out := users.Result{ExternalUser: c.ExternalUser, Account: c.Account}
	var account string
	e := tx.QueryRow(ctx, s.queries["user_lookup"], p.ID, c.ExternalUser).Scan(&account)
	if op == "users" {
		if e == pgx.ErrNoRows {
			account = p.LegacyUsers[c.ExternalUser]
			if account == "" {
				account = "u_" + randomID()
			}
			_, e = tx.Exec(ctx, s.queries["user_insert"], p.ID, c.ExternalUser, account)
		}
		out.Account = account
		return out, e
	}
	if e == pgx.ErrNoRows || (e == nil && account != c.Account) {
		return out, m.Fail("forbidden")
	}
	if e != nil {
		return out, e
	}
	index, identity, e := s.bindDevice(ctx, tx, p, op, c)
	if e != nil {
		return out, e
	}
	out.Identity = &identity
	out.Conversation = s.Config.Conversation
	out.Creator = index == 0
	if op == "credentials" {
		expires := now.Add(time.Duration(c.TTLSeconds) * time.Second).Truncate(time.Microsecond)
		if expires.After(p.ExpiresAt) {
			return out, m.Fail("invalid_expiry")
		}
		out.CredentialID = randomID()
		out.ExpiresAt = &expires
		_, e = tx.Exec(ctx, s.queries["credential_insert"], out.CredentialID, p.ID, c.ExternalUser, c.Account, c.Device, expires)
	} else if op == "revocations" {
		credential, err := s.credential(ctx, tx, c.CredentialID)
		if err == pgx.ErrNoRows {
			return out, m.Fail("forbidden")
		}
		if err != nil {
			return out, err
		}
		if credential.Principal != p.ID || credential.ExternalUser != c.ExternalUser || credential.Account != c.Account || credential.Device != c.Device {
			return out, m.Fail("forbidden")
		}
		_, e = tx.Exec(ctx, s.queries["credential_revoke"], c.CredentialID)
		out.CredentialID = c.CredentialID
		out.Revoked = true
	}
	return out, e
}
func (s *Store) bindDevice(ctx context.Context, tx pgx.Tx, p config.Principal, op string, c users.Command) (int, m.Identity, error) {
	wanted := m.Identity{Scope: m.Scope{Service: s.Config.Service, Account: c.Account, Device: c.Device}, IdentityKey: c.IdentityKey}
	rows, e := tx.Query(ctx, s.queries["identity_lookup"])
	if e != nil {
		return 0, wanted, e
	}
	type binding struct {
		index               int
		identity            m.Identity
		principal, external string
	}
	all := []binding{}
	for rows.Next() {
		b := binding{identity: m.Identity{Scope: m.Scope{Service: s.Config.Service}}}
		e = rows.Scan(&b.index, &b.identity.Scope.Account, &b.identity.Scope.Device, &b.identity.IdentityKey, &b.principal, &b.external)
		if e != nil {
			rows.Close()
			return 0, wanted, e
		}
		all = append(all, b)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return 0, wanted, e
	}
	accountUsed := false
	for _, b := range all {
		if b.identity.Scope.Account == c.Account && b.identity.Scope.Device != c.Device {
			accountUsed = true
			continue
		}
		if b.identity.Scope.Account == c.Account {
			if op == "devices" && b.identity.IdentityKey != c.IdentityKey {
				return 0, wanted, m.Fail("device_conflict")
			}
			if b.principal == "" && op == "devices" && p.LegacyUsers[c.ExternalUser] == c.Account {
				_, e = tx.Exec(ctx, s.queries["identity_adopt"], b.index, p.ID, c.ExternalUser)
				return b.index, b.identity, e
			}
			if b.principal != p.ID || b.external != c.ExternalUser {
				return 0, wanted, m.Fail("forbidden")
			}
			return b.index, b.identity, nil
		}
		if op == "devices" && b.identity.IdentityKey == c.IdentityKey {
			return 0, wanted, m.Fail("device_conflict")
		}
	}
	if accountUsed {
		return 0, wanted, m.Fail("device_conflict")
	}
	if op != "devices" {
		return 0, wanted, m.Fail("device_not_bound")
	}
	if len(all) >= 2 {
		return 0, wanted, m.Fail("device_limit")
	}
	index := len(all)
	_, e = tx.Exec(ctx, s.queries["identity_insert"], index, c.Account, c.Device, c.IdentityKey, p.ID, c.ExternalUser)
	return index, wanted, e
}
