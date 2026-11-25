package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"time"
)

func (s *Store) requireWorkset(ctx context.Context, tx pgx.Tx) error {
	var count, version int
	if e := tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&count, &version); e != nil {
		return e
	}
	if count != 1 || version != 7 || !s.evidenced {
		return m.Fail("workset_not_enabled")
	}
	return nil
}
func (s *Store) readWorkset(ctx context.Context, tx pgx.Tx, index int) (*m.CapacityWorksetState, error) {
	var raw []byte
	if e := tx.QueryRow(ctx, s.queries["workset_read"], index).Scan(&raw); e != nil {
		return nil, e
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var out m.CapacityWorksetState
	if m.Decode(raw, &out) != nil || out.Workset.Validate() != nil || (out.Phase != "prepared" && out.Phase != "confirmed" && out.Phase != "settled") {
		return nil, m.Fail("workset_invalid")
	}
	if e := s.verifyWorkset(ctx, tx, index, out.Workset); e != nil {
		return nil, e
	}
	if out.Phase == "settled" {
		if e := s.worksetComplete(ctx, tx, index, out.Workset); e != nil {
			return nil, e
		}
	}
	return &out, nil
}

// 认证、原件、额度及阶段变化共用原受控事务；成功还须外部候选证据确认。
func (s *Store) CapacityWorkset(ctx context.Context, token, operation string, input *m.CapacityWorkset) (*m.CapacityWorksetState, error) {
	var tx pgx.Tx
	var e error
	if operation == "query" {
		tx, e = s.beginRead(ctx)
	} else {
		tx, e = s.begin(ctx)
	}
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	return s.capacityWorkset(ctx, tx, token, operation, input)
}

func (s *Store) capacityWorkset(ctx context.Context, tx pgx.Tx, token, operation string, input *m.CapacityWorkset) (*m.CapacityWorksetState, error) {
	var e error
	if e = s.requireWorkset(ctx, tx); e != nil {
		return nil, e
	}
	index, deadline, e := s.authenticateDevice(ctx, tx, token)
	if e != nil {
		return nil, e
	}
	old, e := s.readWorkset(ctx, tx, index)
	if e != nil {
		return nil, e
	}
	if operation != "query" {
		if input == nil {
			return nil, m.Fail("workset_invalid")
		}
		if old != nil && old.Workset != *input {
			return nil, m.Fail("workset_conflict")
		}
		if input.Validate() != nil {
			return nil, m.Fail("workset_invalid")
		}
		if e = s.verifyWorkset(ctx, tx, index, *input); e != nil {
			return nil, e
		}
		out := m.CapacityWorksetState{Workset: *input, Phase: "prepared"}
		if old != nil {
			out = *old
		}
		switch operation {
		case "prepare":
			if old == nil {
				var current string
				if e = tx.QueryRow(ctx, s.queries["crypto_context"]).Scan(&current); e != nil {
					return nil, e
				}
				if current != input.Context {
					return nil, m.Fail("workset_context_mismatch")
				}
			}
		case "confirm":
			if old == nil {
				return nil, m.Fail("workset_not_prepared")
			}
			if out.Phase == "prepared" {
				out.Phase = "confirmed"
			}
		case "settle":
			if old == nil || old.Phase == "prepared" {
				return nil, m.Fail("workset_not_confirmed")
			}
			if e = s.worksetComplete(ctx, tx, index, *input); e != nil {
				return nil, e
			}
			out.Phase = "settled"
		default:
			return nil, m.Fail("invalid_request")
		}
		if old == nil || *old != out {
			raw, err := json.Marshal(out)
			if err != nil {
				return nil, err
			}
			if _, e = tx.Exec(ctx, s.queries["workset_write"], index, raw); e != nil {
				return nil, e
			}
		}
		old = &out
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return nil, m.Fail("credential_expired")
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return old, nil
}

// 全局观察沿既有capacity_read；返回两个已授权设备的公开固定范围，无秘密或原件正文。
func (s *Store) CapacityWorksets(ctx context.Context, token string) ([]*m.CapacityWorksetState, error) {
	tx, e := s.beginRead(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	p, ok := s.Config.AuthenticateBusiness(token, time.Now())
	if !ok {
		return nil, m.Fail("unauthorized")
	}
	if !p.CapacityRead {
		return nil, m.Fail("forbidden")
	}
	if e = s.requireWorkset(ctx, tx); e != nil {
		return nil, e
	}
	out := make([]*m.CapacityWorksetState, 2)
	for i := range out {
		if out[i], e = s.readWorkset(ctx, tx, i); e != nil {
			return nil, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return out, nil
}
