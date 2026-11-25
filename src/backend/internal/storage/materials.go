package storage

import (
	"context"
	"encoding/json"
	m "rocket-im/service/internal/messaging"
)

func (s *Store) Material(ctx context.Context, index int, input *m.Material) (*m.Material, error) {
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if e = tx.QueryRow(ctx, s.queries["material"], index).Scan(&raw); e != nil {
		return nil, e
	}
	var old *m.Material
	if raw != nil {
		if e = json.Unmarshal(raw, &old); e != nil {
			return nil, e
		}
	}
	if input != nil {
		identity, e := s.identity(ctx, tx, index)
		if e != nil {
			return nil, e
		}
		if input.Identity != identity || !m.Hex(input.KeyPackage, 1, 96*1024) {
			return nil, m.Fail("identity_mismatch")
		}
		if old != nil && *old != *input {
			return nil, m.Fail("material_conflict")
		}
		raw, e = json.Marshal(input)
		if e != nil {
			return nil, e
		}
		if _, e = tx.Exec(ctx, s.queries["put_material"], index, raw); e != nil {
			return nil, e
		}
		old = input
	}
	return old, tx.Commit(ctx)
}
func (s *Store) Welcome(ctx context.Context, index int, input *m.Welcome) (*m.Welcome, error) {
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	var old *string
	if e = tx.QueryRow(ctx, s.queries["welcome"]).Scan(&old); e != nil {
		return nil, e
	}
	if input != nil {
		if index != 0 {
			return nil, m.Fail("forbidden")
		}
		if !m.Hex(input.Welcome, 1, 96*1024) {
			return nil, m.Fail("invalid_request")
		}
		if old != nil && *old != input.Welcome {
			return nil, m.Fail("welcome_conflict")
		}
		// 创建者只能向已经公布固定公钥材料的对端发布一次Welcome。
		var material []byte
		if e = tx.QueryRow(ctx, s.queries["material"], 1).Scan(&material); e != nil {
			return nil, e
		}
		if material == nil {
			return nil, m.Fail("peer_not_ready")
		}
		if _, e = tx.Exec(ctx, s.queries["put_welcome"], input.Welcome); e != nil {
			return nil, e
		}
		old = &input.Welcome
	}
	var out *m.Welcome
	if old != nil {
		out = &m.Welcome{Welcome: *old}
	}
	return out, tx.Commit(ctx)
}
