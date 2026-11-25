package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"time"
)

func (s *Store) requireWorkset(ctx context.Context, tx pgx.Tx) error {
	_, e := s.worksetSchema(ctx, tx)
	return e
}
func (s *Store) readWorkset(ctx context.Context, tx pgx.Tx, index int) (*m.CapacityWorksetState, error) {
	current, _, e := s.readWorksetChain(ctx, tx, index)
	return current, e
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
	old, history, e := s.readWorksetChain(ctx, tx, index)
	if e != nil {
		return nil, e
	}
	if operation != "query" {
		if input == nil {
			return nil, m.Fail("workset_invalid")
		}
		if old != nil && old.Workset.ID == input.ID && old.Workset != *input {
			return nil, m.Fail("workset_conflict")
		}
		// 旧ID精确重试只返回旧终态，不更新当前轮或重新分配历史。
		for _, record := range history {
			if record.Workset.ID == input.ID {
				if record.Workset != *input {
					return nil, m.Fail("workset_conflict")
				}
				if operation != "prepare" && operation != "confirm" && operation != "settle" {
					return nil, m.Fail("invalid_request")
				}
				if !deadline.IsZero() && !time.Now().Before(deadline) {
					return nil, m.Fail("credential_expired")
				}
				if e = tx.Commit(ctx); e != nil {
					return nil, e
				}
				return &record, nil
			}
		}
		if input.Validate() != nil {
			return nil, m.Fail("workset_invalid")
		}
		if old != nil && old.Workset != *input {
			if operation != "prepare" {
				return nil, m.Fail("workset_conflict")
			}
			if e = s.appendWorksetPredecessor(ctx, tx, index, *old, *input); e != nil {
				return nil, e
			}
			old = nil
		} else if old == nil && input.Version != m.WorksetVersion {
			return nil, m.Fail("workset_conflict")
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
