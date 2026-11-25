package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recoveryFixture struct {
	s    *Store
	keys [2]ed25519.PrivateKey
	q    m.RecoveryReservation
}

func recoveryStore(t *testing.T) *recoveryFixture {
	return recoveryStoreConfig(t, func(c config.Config) config.Config { return c })
}
func recoveryStoreConfig(t *testing.T, change func(config.Config) config.Config) *recoveryFixture {
	t.Helper()
	c := testConfig(t)
	f := &recoveryFixture{}
	for i := range 2 {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		f.keys[i] = key
		c.Devices[i].IdentityKey = hex.EncodeToString(pub)
	}
	var e error
	c = change(c)
	f.s, e = Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.s.Close)
	if _, e = f.s.Material(context.Background(), 1, &m.Material{Identity: c.Identity(1), KeyPackage: "aabb"}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Welcome(context.Background(), 0, &m.Welcome{Welcome: "aabb"}); e != nil {
		t.Fatal(e)
	}
	f.q = m.RecoveryReservation{Version: "successor-alpha1", ID: "round-1", Target: c.Identity(0), Peer: c.Identity(1), Conversation: "chat", OldContext: "initial", Request: "unknown", RequestHash: strings.Repeat("01", 32), Deadline: strconv.FormatInt(time.Now().Add(10*time.Minute).UnixMilli(), 10)}
	return f
}
func (f *recoveryFixture) packet(t *testing.T, index int, b m.RecoveryBody) string {
	t.Helper()
	sender := f.s.Config.Identity(index)
	raw, e := json.Marshal([]any{sender, b})
	if e != nil {
		t.Fatal(e)
	}
	sig := ed25519.Sign(f.keys[index], append([]byte("Rocket-IM/SDK/recovery/v1\x00"), raw...))
	frame, e := json.Marshal(m.RecoveryFrame{Sender: sender, Body: b, Signature: hex.EncodeToString(sig)})
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(frame)
}
func (f *recoveryFixture) publish(t *testing.T, index int, key string, b m.RecoveryBody) *m.RecoveryRound {
	t.Helper()
	in := m.RecoveryPublish{ID: f.q.ID, Kind: key, Packet: f.packet(t, index, b)}
	r, e := f.s.PublishRecovery(context.Background(), index, in)
	if e != nil {
		t.Fatal(key, e)
	}
	again, e := f.s.PublishRecovery(context.Background(), index, in)
	if e != nil || !m.Equal(r, again) {
		t.Fatal("exact material replay", e)
	}
	return r
}
func (f *recoveryFixture) offer(t *testing.T) *m.RecoveryRound {
	t.Helper()
	if _, e := f.s.ReserveRecovery(context.Background(), 0, f.q); e != nil {
		t.Fatal(e)
	}
	q := f.q
	return f.publish(t, 0, "offer", m.RecoveryBody{Kind: "offer", Offer: &m.RecoveryOffer{Target: q.Target, Peer: q.Peer, Conversation: q.Conversation, OldContext: q.OldContext, Previous: q.Previous, Request: q.Request, RequestHash: q.RequestHash, KeyPackage: "aabb", Transport: &m.RecoveryTransport{Version: q.Version, RoundID: q.ID, Deadline: q.Deadline}}})
}
func TestRecoveryMaterialsRolesOrderAndOldQueueFacts(t *testing.T) {
	f := recoveryStore(t)
	ctx := context.Background()
	s := f.s
	old, e := s.Accept(ctx, 0, send("old"))
	if e != nil {
		t.Fatal(e)
	}
	r := f.offer(t)
	context := *r.Context
	_, e = s.PublishRecovery(ctx, 1, m.RecoveryPublish{ID: f.q.ID, Kind: "ready", Packet: f.packet(t, 1, m.RecoveryBody{Kind: "ready", Context: context, ApprovalHash: strings.Repeat("00", 32)})})
	requireCode(t, e, "recovery_role_mismatch")
	_, e = s.PublishRecovery(ctx, 0, m.RecoveryPublish{ID: f.q.ID, Kind: "ready", Packet: f.packet(t, 0, m.RecoveryBody{Kind: "ready", Context: context, ApprovalHash: strings.Repeat("00", 32)})})
	requireCode(t, e, "recovery_order")
	r = f.publish(t, 1, "approval", m.RecoveryBody{Kind: "approval", Context: context, Welcome: "aabb"})
	_, e = s.Accept(ctx, 0, send("unaccepted"))
	requireCode(t, e, "context_not_accepted")
	exact, e := s.Accept(ctx, 0, send("old"))
	if e != nil || exact != old {
		t.Fatal("accepted fact lost", e)
	}
	_, e = s.Processed(ctx, 1, m.Processed{Sequence: "1", Disposition: "context_retired"})
	requireCode(t, e, "context_not_retired")
	r = f.publish(t, 0, "ready", m.RecoveryBody{Kind: "ready", Context: context, ApprovalHash: m.Digest([]byte(r.Materials["approval"]))})
	_, e = s.PublishRecovery(ctx, 1, m.RecoveryPublish{ID: f.q.ID, Kind: "close_peer", Packet: f.packet(t, 1, m.RecoveryBody{Kind: "close", Context: context})})
	requireCode(t, e, "recovery_must_finish")
	r = f.publish(t, 1, "commit", m.RecoveryBody{Kind: "commit", Context: context, ReadyHash: m.Digest([]byte(r.Materials["ready"]))})
	installed := m.RecoveryBody{Kind: "installed", Context: context, ReceiptHash: m.Digest([]byte(r.Materials["commit"]))}
	f.publish(t, 1, "installed_peer", installed)
	fresh := send("new")
	fresh.Envelope.Context = context
	_, e = s.Accept(ctx, 0, fresh)
	requireCode(t, e, "context_not_accepted")
	r = f.publish(t, 0, "installed_target", installed)
	if r.Status != "complete" {
		t.Fatal(r.Status)
	}
	if _, e = s.Accept(ctx, 0, fresh); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = s.Processed(ctx, 1, m.Processed{Sequence: "1", Disposition: "context_retired"}); e != nil {
			t.Fatal(e)
		}
	}
	_, e = s.Processed(ctx, 1, m.Processed{Sequence: "1"})
	requireCode(t, e, "disposition_conflict")
	p, e := s.Page(ctx, 0, m.Poll{After: "0", Limit: 4})
	if e != nil || len(p.Events) != 1 || p.Events[0].Kind != "unavailable" {
		t.Fatal(p, e)
	}
	var delivered, retired bool
	if e = s.Pool.QueryRow(ctx, "SELECT delivered,context_retired FROM alpha_messages WHERE message_id='old'").Scan(&delivered, &retired); e != nil || delivered || !retired {
		t.Fatal("false delivery", e)
	}
	before, _ := s.Recovery(ctx, 0, m.RecoveryQuery{})
	for _, packet := range []string{"ab", r.Materials["approval"][:len(r.Materials["approval"])-2] + "00"} {
		if _, e = s.PublishRecovery(ctx, 1, m.RecoveryPublish{ID: f.q.ID, Kind: "approval", Packet: packet}); e == nil {
			t.Fatal("tamper accepted")
		}
	}
	after, _ := s.Recovery(ctx, 0, m.RecoveryQuery{})
	if !m.Equal(before, after) {
		t.Fatal("invalid material changed state")
	}
}
func TestRecoveryReservationConcurrentScopeAndDeadline(t *testing.T) {
	f := recoveryStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := range 12 {
		wg.Go(func() {
			q := f.q
			q.ID = "race-" + strconv.Itoa(i)
			_, e := f.s.ReserveRecovery(ctx, 0, q)
			results <- e
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else {
			requireCode(t, e, "recovery_active")
		}
	}
	if successes != 1 {
		t.Fatal(successes)
	}
	for i := range 6 {
		q := f.q
		switch i {
		case 0:
			q.Target.Scope.Service = "wrong"
		case 1:
			q.Peer.Scope.Account = "wrong"
		case 2:
			q.Target.Scope.Device = "wrong"
		case 3:
			q.Conversation = "wrong"
		case 4:
			q.Target.IdentityKey = strings.Repeat("00", 32)
		case 5:
			q.Peer.IdentityKey = q.Target.IdentityKey
		}
		_, e := f.s.ReserveRecovery(ctx, 0, q)
		requireCode(t, e, "recovery_scope_mismatch")
	}
	q := f.q
	q.Deadline = "1"
	_, e := f.s.ReserveRecovery(ctx, 0, q)
	requireCode(t, e, "recovery_deadline")
}
func TestRecoveryRejectPersistsSignedCloseAndAllowsNextRound(t *testing.T) {
	f := recoveryStore(t)
	r := f.offer(t)
	context := *r.Context
	f.publish(t, 1, "close_peer", m.RecoveryBody{Kind: "close", Context: context})
	r = f.publish(t, 0, "close_target", m.RecoveryBody{Kind: "close", Context: context})
	if r.Status != "closed" {
		t.Fatal(r.Status)
	}
	q := f.q
	q.ID = "round-2"
	q.Previous = &context
	if _, e := f.s.ReserveRecovery(contextBackground(), 0, q); e != nil {
		t.Fatal(e)
	}
	_, e := f.s.PublishRecovery(contextBackground(), 1, m.RecoveryPublish{ID: f.q.ID, Kind: "approval", Packet: f.packet(t, 1, m.RecoveryBody{Kind: "approval", Context: context, Welcome: "aabb"})})
	requireCode(t, e, "recovery_closed")
}
func contextBackground() context.Context { return context.Background() }
