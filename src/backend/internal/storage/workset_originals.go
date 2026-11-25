package storage

import (
	"context"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"strconv"
)

func (s *Store) verifyWorkset(ctx context.Context, tx pgx.Tx, index int, w m.CapacityWorkset) error {
	own, e := s.identity(ctx, tx, index)
	if e != nil {
		return e
	}
	if own != w.Owner || w.Conversation != s.Config.Conversation {
		return m.Fail("scope_mismatch")
	}
	first, _ := m.Number(w.First)
	last, _ := m.Number(w.Last)
	var tail, processed int64
	if e = tx.QueryRow(ctx, s.queries["mailbox_state"], index).Scan(&tail, &processed); e != nil {
		return e
	}
	if first > processed+1 || last > tail {
		return m.Fail("workset_not_contiguous")
	}
	rows, e := tx.Query(ctx, s.queries["workset_originals"], index, first, last)
	if e != nil {
		return e
	}
	fields := make([][]string, 0, last-first+1)
	for rows.Next() {
		var raw, acceptedRaw []byte
		var request, message, digest, disposition string
		var accepted int64
		var delivered, retired bool
		if e = rows.Scan(&raw, &request, &message, &accepted, &digest, &acceptedRaw, &disposition, &delivered, &retired); e != nil {
			rows.Close()
			return e
		}
		var event m.Event
		var envelope m.Envelope
		if m.Decode(raw, &event) != nil || m.Decode(acceptedRaw, &envelope) != nil ||
			event.Envelope != nil || (event.Kind != "delivered" && event.Kind != "unavailable") ||
			(event.Kind == "delivered" && (!delivered || retired)) || (event.Kind == "unavailable" && (!retired || delivered)) ||
			event.Sequence != strconv.FormatInt(first+int64(len(fields)), 10) ||
			event.Acceptance.RequestID != request || event.Acceptance.MessageID != message ||
			event.Acceptance.Sequence != strconv.FormatInt(accepted, 10) || event.Acceptance.EnvelopeHash != digest ||
			envelope.Service != own.Scope.Service || envelope.Conversation != w.Conversation ||
			envelope.SenderAccount != own.Scope.Account || envelope.SenderDevice != own.Scope.Device ||
			(first+int64(len(fields)) <= processed && disposition != "received") {
			rows.Close()
			return m.Fail("workset_original_mismatch")
		}
		// 原接受摘要是规范Envelope编码的摘要，不能只核对调用者或信箱拷贝。
		if m.WorksetHash(envelope) != digest {
			rows.Close()
			return m.Fail("workset_original_mismatch")
		}
		fields = append(fields, []string{event.Sequence, event.Kind, request, message, event.Acceptance.Sequence, digest, envelope.Context})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if int64(len(fields)) != last-first+1 || m.WorksetHash([]any{"rocket-im/control-originals/1", fields}) != w.OriginalsHash {
		return m.Fail("workset_original_mismatch")
	}
	return nil
}
func (s *Store) worksetComplete(ctx context.Context, tx pgx.Tx, index int, w m.CapacityWorkset) error {
	first, _ := m.Number(w.First)
	last, _ := m.Number(w.Last)
	var complete bool
	if e := tx.QueryRow(ctx, s.queries["workset_complete"], index, first, last).Scan(&complete); e != nil {
		return e
	}
	if !complete {
		return m.Fail("workset_not_complete")
	}
	return nil
}

// 同一完整PG行未来最长阶段的差额；无工作集时不预占任意未来元数据。
func (s *Store) worksetGrowth(ctx context.Context, tx pgx.Tx) (int64, error) {
	var growth int64
	e := tx.QueryRow(ctx, s.queries["workset_growth"]).Scan(&growth)
	return growth, e
}
