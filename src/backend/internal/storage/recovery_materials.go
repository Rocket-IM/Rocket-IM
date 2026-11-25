package storage

import (
	"encoding/json"
	m "rocket-im/service/internal/messaging"
)

func advanceRecovery(r *m.RecoveryRound, own m.Identity, b m.RecoveryBody, packet string) error {
	bad := func() error { return m.Fail("recovery_material_conflict") }
	target := own == r.Reservation.Target
	if own != r.Reservation.Target && own != r.Reservation.Peer {
		return m.Fail("recovery_identity_mismatch")
	}
	if b.Kind != "offer" && (r.Context == nil || b.Context != *r.Context) {
		return bad()
	}
	if r.Status == "closing" && b.Kind != "close" {
		return m.Fail("recovery_closed")
	}
	switch b.Kind {
	case "offer":
		if !target || r.Status != "reserved" {
			return m.Fail("recovery_role_mismatch")
		}
		o := b.Offer
		q := r.Reservation
		if o.Target != q.Target || o.Peer != q.Peer || o.Conversation != q.Conversation || o.OldContext != q.OldContext || !m.Equal(o.Previous, q.Previous) || o.Request != q.Request || o.RequestHash != q.RequestHash {
			return bad()
		}
		if o.Transport == nil || *o.Transport != (m.RecoveryTransport{Version: q.Version, RoundID: q.ID, Deadline: q.Deadline}) {
			return bad()
		}
		raw, e := json.Marshal(o)
		if e != nil {
			return e
		}
		context := m.Digest(raw)
		r.Context = &context
		r.Status = "offered"
	case "approval":
		if target {
			return m.Fail("recovery_role_mismatch")
		}
		if r.Status != "offered" {
			return m.Fail("recovery_order")
		}
		r.Status = "approved"
	case "ready":
		if !target {
			return m.Fail("recovery_role_mismatch")
		}
		if r.Status != "approved" {
			return m.Fail("recovery_order")
		}
		if b.ApprovalHash != m.Digest([]byte(r.Materials["approval"])) {
			return bad()
		}
		r.Status = "ready"
	case "commit":
		if target {
			return m.Fail("recovery_role_mismatch")
		}
		if r.Status != "ready" {
			return m.Fail("recovery_order")
		}
		if b.ReadyHash != m.Digest([]byte(r.Materials["ready"])) {
			return bad()
		}
		r.Status = "committed"
	case "installed":
		if r.Status != "committed" {
			return m.Fail("recovery_order")
		}
		if b.ReceiptHash != m.Digest([]byte(r.Materials["commit"])) {
			return bad()
		}
	case "close":
		if r.Materials["ready"] != "" {
			return m.Fail("recovery_must_finish")
		}
		if r.Materials["offer"] == "" {
			return m.Fail("recovery_order")
		}
		r.Status = "closing"
	default:
		return m.Fail("invalid_recovery_material")
	}
	return nil
}
