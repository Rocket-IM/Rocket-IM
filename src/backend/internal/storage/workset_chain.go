package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
)

func (s *Store) worksetSchema(ctx context.Context, tx pgx.Tx) (int, error) {
	var count, version int
	if e := tx.QueryRow(ctx, s.queries["schema_version"]).Scan(&count, &version); e != nil {
		return 0, e
	}
	if count != 1 || (version != 7 && version != 8) || !s.evidenced {
		return 0, m.Fail("workset_not_enabled")
	}
	return version, nil
}

// 所有历史与当前轮一并核验；旧轮依然依赖幸存接受原件和received事实。
func (s *Store) readWorksetChain(ctx context.Context, tx pgx.Tx, index int) (*m.CapacityWorksetState, []m.CapacityWorksetState, error) {
	version, e := s.worksetSchema(ctx, tx)
	if e != nil {
		return nil, nil, e
	}
	var raw []byte
	if e = tx.QueryRow(ctx, s.queries["workset_read"], index).Scan(&raw); e != nil {
		return nil, nil, e
	}
	var current *m.CapacityWorksetState
	if len(raw) != 0 {
		var out m.CapacityWorksetState
		if m.Decode(raw, &out) != nil {
			return nil, nil, m.Fail("workset_invalid")
		}
		current = &out
	}
	history := []m.CapacityWorksetState{}
	if version == 8 {
		if e = tx.QueryRow(ctx, s.queries["workset_history_read"], index).Scan(&raw); e != nil {
			return nil, nil, e
		}
		var records []json.RawMessage
		if json.Unmarshal(raw, &records) != nil || records == nil || len(records) >= 512 {
			return nil, nil, m.Fail("workset_invalid")
		}
		for _, record := range records {
			var state m.CapacityWorksetState
			if m.Decode(record, &state) != nil {
				return nil, nil, m.Fail("workset_invalid")
			}
			history = append(history, state)
		}
	}
	all := append([]m.CapacityWorksetState{}, history...)
	if current != nil {
		all = append(all, *current)
	} else if len(history) != 0 {
		return nil, nil, m.Fail("workset_invalid")
	}
	for i, state := range all {
		if state.Workset.Validate() != nil || (state.Phase != "prepared" && state.Phase != "confirmed" && state.Phase != "settled") ||
			(i < len(history) && state.Phase != "settled") ||
			(i == 0 && state.Workset.Version != m.WorksetVersion) || (i > 0 && !state.Workset.Follows(all[i-1].Workset)) {
			return nil, nil, m.Fail("workset_invalid")
		}
		if e = s.verifyWorkset(ctx, tx, index, state.Workset); e != nil {
			return nil, nil, e
		}
		if state.Phase == "settled" {
			if e = s.worksetComplete(ctx, tx, index, state.Workset); e != nil {
				return nil, nil, e
			}
		}
	}
	return current, history, nil
}

// 新prepare同时承载原认证SDK对前轮settled的持久观察确认；不声称跨库共识。
// 只有SDK按协议保存终态后才会生成这一绑定；即便丢回复，旧终态仍永久保留。
func (s *Store) appendWorksetPredecessor(ctx context.Context, tx pgx.Tx, index int, old m.CapacityWorksetState, next m.CapacityWorkset) error {
	if !next.Follows(old.Workset) {
		return m.Fail("workset_conflict")
	}
	version, e := s.worksetSchema(ctx, tx)
	if e != nil {
		return e
	}
	if version != 8 {
		return m.Fail("workset_repeat_not_enabled")
	}
	if old.Phase != "settled" {
		return m.Fail("workset_not_settled")
	}
	raw, e := json.Marshal(old)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, s.queries["workset_history_append"], index, raw)
	return e
}
