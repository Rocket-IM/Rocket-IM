package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"time"
)

func (s *Store) recoveryRound(ctx context.Context, tx pgx.Tx, id *string) (*m.RecoveryRound, error) {
	var raw []byte
	var err error
	if id == nil {
		err = tx.QueryRow(ctx, s.queries["recovery_latest"]).Scan(&raw)
	} else {
		err = tx.QueryRow(ctx, s.queries["recovery_find"], *id).Scan(&raw)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var round m.RecoveryRound
	if err = json.Unmarshal(raw, &round); err != nil {
		return nil, err
	}
	return &round, nil
}
func (s *Store) Recovery(ctx context.Context, index int, input m.RecoveryQuery) (*m.RecoveryRound, error) {
	if input.ID != nil && !m.ID(*input.ID) {
		return nil, m.Fail("invalid_request")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.identity(ctx, tx, index); e != nil {
		return nil, e
	}
	r, e := s.recoveryRound(ctx, tx, input.ID)
	if e != nil {
		return nil, e
	}
	return r, tx.Commit(ctx)
}
func (s *Store) ReserveRecovery(ctx context.Context, index int, input m.RecoveryReservation) (*m.RecoveryRound, error) {
	if input.Version != "successor-alpha1" || !m.ID(input.ID) || !m.ID(input.Request) || !m.Hex(input.RequestHash, 32, 32) || (input.OldContext != "initial" && !m.Hex(input.OldContext, 32, 32)) {
		return nil, m.Fail("invalid_recovery_reservation")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	own, e := s.identity(ctx, tx, index)
	if e != nil {
		return nil, e
	}
	peer, e := s.identity(ctx, tx, 1-index)
	if e != nil {
		return nil, e
	}
	if input.Target != own || input.Peer != peer || input.Conversation != s.Config.Conversation {
		return nil, m.Fail("recovery_scope_mismatch")
	}
	prior, e := s.recoveryRound(ctx, tx, &input.ID)
	if e != nil {
		return nil, e
	}
	if prior != nil {
		if !m.Equal(prior.Reservation, input) {
			return nil, m.Fail("recovery_conflict")
		}
		return prior, tx.Commit(ctx)
	}
	deadline, e := m.Number(input.Deadline)
	if e != nil || deadline <= time.Now().UnixMilli() || deadline > time.Now().Add(15*time.Minute).UnixMilli() {
		return nil, m.Fail("recovery_deadline")
	}
	var current string
	if e = tx.QueryRow(ctx, s.queries["crypto_context"]).Scan(&current); e != nil {
		return nil, e
	}
	if input.OldContext != current {
		return nil, m.Fail("recovery_context_mismatch")
	}
	latest, e := s.recoveryRound(ctx, tx, nil)
	if e != nil {
		return nil, e
	}
	if latest != nil {
		if latest.Status != "complete" && latest.Status != "closed" {
			return nil, m.Fail("recovery_active")
		}
		if !m.Equal(input.Previous, latest.Context) {
			return nil, m.Fail("recovery_predecessor_mismatch")
		}
	} else if input.Previous != nil {
		return nil, m.Fail("recovery_predecessor_mismatch")
	}
	count, size, e := s.recoveryUsage(ctx, tx)
	if e != nil {
		return nil, e
	}
	if count >= recoveryRoundLimit || size > recoveryJSONLimit {
		return nil, m.Fail("recovery_limit")
	}
	round := &m.RecoveryRound{Reservation: input, Status: "reserved", Materials: map[string]string{}}
	raw, e := json.Marshal(round)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, s.queries["recovery_insert"], count+1, input.ID, raw); e != nil {
		return nil, e
	}
	return round, tx.Commit(ctx)
}
func (s *Store) PublishRecovery(ctx context.Context, index int, input m.RecoveryPublish) (*m.RecoveryRound, error) {
	if !m.ID(input.ID) {
		return nil, m.Fail("invalid_request")
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	own, e := s.identity(ctx, tx, index)
	if e != nil {
		return nil, e
	}
	r, e := s.recoveryRound(ctx, tx, &input.ID)
	if e != nil {
		return nil, e
	}
	if r == nil {
		return nil, m.Fail("recovery_missing")
	}
	b, e := m.ParseRecovery(input.Packet, own)
	if e != nil {
		return nil, e
	}
	key := b.Kind
	if b.Kind == "close" || b.Kind == "installed" {
		if own == r.Reservation.Target {
			key += "_target"
		} else {
			key += "_peer"
		}
	}
	if input.Kind != key {
		return nil, m.Fail("recovery_role_mismatch")
	}
	if old, ok := r.Materials[key]; ok {
		if old != input.Packet {
			return nil, m.Fail("recovery_material_conflict")
		}
		return r, tx.Commit(ctx)
	}
	latest, e := s.recoveryRound(ctx, tx, nil)
	if e != nil {
		return nil, e
	}
	if latest == nil || latest.Reservation.ID != input.ID || r.Status == "complete" || r.Status == "closed" {
		return nil, m.Fail("recovery_closed")
	}
	if e = advanceRecovery(r, own, b, input.Packet); e != nil {
		return nil, e
	}
	r.Materials[key] = input.Packet
	if r.Materials["close_target"] != "" && r.Materials["close_peer"] != "" {
		r.Status = "closed"
	}
	if r.Materials["installed_target"] != "" && r.Materials["installed_peer"] != "" {
		r.Status = "complete"
		if _, e = tx.Exec(ctx, s.queries["activate_context"], *r.Context); e != nil {
			return nil, e
		}
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	if len(raw) > m.MaxFrame-2048 {
		return nil, m.Fail("recovery_limit")
	}
	if _, e = tx.Exec(ctx, s.queries["recovery_update"], input.ID, raw); e != nil {
		return nil, e
	}
	return r, tx.Commit(ctx)
}

// 旧上下文冻结后只有原已接受原件可精确重试；新原件由Accept先查幂等再调用这里。
func (s *Store) allowContext(ctx context.Context, tx pgx.Tx, context string) error {
	var current string
	if e := tx.QueryRow(ctx, s.queries["crypto_context"]).Scan(&current); e != nil {
		return e
	}
	r, e := s.recoveryRound(ctx, tx, nil)
	if e != nil {
		return e
	}
	if context != current {
		return m.Fail("context_not_accepted")
	}
	if contextFrozen(context, r) {
		return m.Fail("context_not_accepted")
	}
	return nil
}

func contextFrozen(context string, r *m.RecoveryRound) bool {
	return r != nil && r.Reservation.OldContext == context && r.Materials["approval"] != ""
}
