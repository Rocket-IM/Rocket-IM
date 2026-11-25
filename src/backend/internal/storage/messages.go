package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	m "rocket-im/service/internal/messaging"
	"strconv"
)

func (s *Store) Accept(ctx context.Context, index int, input m.Send) (m.Acceptance, error) {
	e := input.Envelope
	if !m.ID(input.RequestID) || !m.ID(e.MessageID) || !m.Hex(e.Ciphertext, 1, 96*1024) || (e.Context != "initial" && !m.Hex(e.Context, 32, 32)) {
		return m.Acceptance{}, m.Fail("invalid_request")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return m.Acceptance{}, err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	tx, err := s.begin(ctx)
	if err != nil {
		return m.Acceptance{}, err
	}
	defer tx.Rollback(ctx)
	identity, err := s.identity(ctx, tx, index)
	if err != nil {
		return m.Acceptance{}, err
	}
	own := identity.Scope
	if e.Service != own.Service || e.Conversation != s.Config.Conversation || e.SenderAccount != own.Account || e.SenderDevice != own.Device {
		return m.Acceptance{}, m.Fail("scope_mismatch")
	}
	var prior m.Acceptance
	var seq int64
	err = tx.QueryRow(ctx, s.queries["message_lookup"], index, input.RequestID, e.MessageID).Scan(&prior.RequestID, &prior.MessageID, &seq, &prior.EnvelopeHash)
	if err == nil {
		if prior.RequestID != input.RequestID || prior.MessageID != e.MessageID || prior.EnvelopeHash != digest {
			return m.Acceptance{}, m.Fail("idempotency_conflict")
		}
		prior.Sequence = strconv.FormatInt(seq, 10)
		return prior, tx.Commit(ctx)
	}
	if err != pgx.ErrNoRows {
		return m.Acceptance{}, err
	}
	if err = s.allowContext(ctx, tx, e.Context); err != nil {
		return m.Acceptance{}, err
	}
	var welcome *string
	if err = tx.QueryRow(ctx, s.queries["welcome"]).Scan(&welcome); err != nil {
		return m.Acceptance{}, err
	}
	if welcome == nil && e.Context == "initial" {
		return m.Acceptance{}, m.Fail("group_not_ready")
	}
	if err = tx.QueryRow(ctx, s.queries["lock"]).Scan(&seq); err != nil {
		return m.Acceptance{}, err
	}
	if seq >= messageLimit {
		return m.Acceptance{}, m.Fail("message_limit")
	}
	seq++
	ack := m.Acceptance{RequestID: input.RequestID, MessageID: e.MessageID, Sequence: strconv.FormatInt(seq, 10), EnvelopeHash: digest}
	if _, err = tx.Exec(ctx, s.queries["insert_message"], index, input.RequestID, e.MessageID, seq, raw, digest); err != nil {
		return m.Acceptance{}, err
	}
	if _, err = tx.Exec(ctx, s.queries["accept"], seq); err != nil {
		return m.Acceptance{}, err
	}
	if err = s.append(ctx, tx, 1-index, m.Event{Kind: "message", Acceptance: ack, Envelope: &e}); err != nil {
		return m.Acceptance{}, err
	}
	return ack, tx.Commit(ctx)
}
func (s *Store) append(ctx context.Context, tx pgx.Tx, index int, event m.Event) error {
	var seq int64
	if e := tx.QueryRow(ctx, s.queries["next_sequence"], index).Scan(&seq); e != nil {
		return e
	}
	event.Sequence = strconv.FormatInt(seq, 10)
	raw, e := json.Marshal(event)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, s.queries["append"], index, seq, raw)
	return e
}
func (s *Store) Page(ctx context.Context, index int, input m.Poll) (m.Page, error) {
	out := m.Page{After: input.After, Next: input.After, Events: []m.Event{}}
	after, e := m.Number(input.After)
	if e != nil || input.Limit < 1 || input.Limit > 4 {
		return out, m.Fail("invalid_cursor")
	}
	tx, e := s.beginRead(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var tail, processed int64
	if e = tx.QueryRow(ctx, s.queries["mailbox_state"], index).Scan(&tail, &processed); e != nil {
		return out, e
	}
	upper := tail
	if input.Upper != nil {
		upper, e = m.Number(*input.Upper)
		if e != nil {
			return out, e
		}
	}
	if after > upper || upper > tail {
		return out, m.Fail("invalid_cursor")
	}
	out.Upper = strconv.FormatInt(upper, 10)
	rows, e := tx.Query(ctx, s.queries["page"], index, after, upper, input.Limit)
	if e != nil {
		return out, e
	}
	size := 0
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return out, e
		}
		if size+len(raw) > m.MaxFrame-2048 {
			break
		}
		size += len(raw)
		var event m.Event
		if e = json.Unmarshal(raw, &event); e != nil {
			rows.Close()
			return out, e
		}
		out.Events = append(out.Events, event)
		out.Next = event.Sequence
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Store) Processed(ctx context.Context, index int, input m.Processed) (m.Processed, error) {
	disposition := input.Disposition
	if disposition == "" {
		disposition = "received"
	}
	if disposition != "received" && disposition != "context_retired" {
		return input, m.Fail("invalid_disposition")
	}
	sequence, e := m.Number(input.Sequence)
	if e != nil {
		return input, e
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return input, e
	}
	defer tx.Rollback(ctx)
	var tail, processed int64
	if e = tx.QueryRow(ctx, s.queries["mailbox_state"], index).Scan(&tail, &processed); e != nil {
		return input, e
	}
	if sequence < 1 || sequence > tail || sequence > processed+1 {
		return input, m.Fail("invalid_cursor")
	}
	if sequence <= processed {
		var old string
		if e = tx.QueryRow(ctx, s.queries["mailbox_disposition"], index, sequence).Scan(&old); e != nil {
			return input, e
		}
		if old != disposition {
			return input, m.Fail("disposition_conflict")
		}
		return input, tx.Commit(ctx)
	}
	var raw []byte
	if e = tx.QueryRow(ctx, s.queries["page"], index, processed, sequence, 1).Scan(&raw); e != nil {
		return input, e
	}
	var event m.Event
	if e = json.Unmarshal(raw, &event); e != nil {
		return input, e
	}
	if event.Kind == "message" {
		var request string
		accepted, e := m.Number(event.Acceptance.Sequence)
		if e != nil {
			return input, e
		}
		query, kind := "delivered", "delivered"
		if disposition == "context_retired" {
			var current string
			if e = tx.QueryRow(ctx, s.queries["crypto_context"]).Scan(&current); e != nil {
				return input, e
			}
			if event.Envelope == nil || event.Envelope.Context == current {
				return input, m.Fail("context_not_retired")
			}
			query, kind = "message_retired", "unavailable"
		}
		if e = tx.QueryRow(ctx, s.queries[query], 1-index, accepted, event.Acceptance.EnvelopeHash).Scan(&request); e != nil {
			return input, e
		}
		if e = s.append(ctx, tx, 1-index, m.Event{Kind: kind, Acceptance: event.Acceptance}); e != nil {
			return input, e
		}
	} else if disposition != "received" {
		return input, m.Fail("invalid_disposition")
	}
	if _, e = tx.Exec(ctx, s.queries["set_disposition"], index, sequence, disposition); e != nil {
		return input, e
	}
	if _, e = tx.Exec(ctx, s.queries["processed"], index, sequence); e != nil {
		return input, e
	}
	return input, tx.Commit(ctx)
}
