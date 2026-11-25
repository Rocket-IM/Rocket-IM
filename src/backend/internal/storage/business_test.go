package storage

import (
	"context"
	"encoding/json"
	"reflect"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/users"
	"strings"
	"sync"
	"testing"
	"time"
)

func businessConfig(c config.Config) config.Config {
	c.Business = &config.Business{CredentialKeyEnv: "TEST_KEY", CredentialKey: strings.Repeat("ab", 32), Principals: []config.Principal{
		{ID: "shop", TokenSHA256: strings.Repeat("12", 32), NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour * 2), LegacyUsers: map[string]string{"legacy_alice": "alice", "legacy_bob": "bob"}},
		{ID: "other", TokenSHA256: strings.Repeat("34", 32), NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour * 2)},
	}}
	return c
}
func freshBusiness(t *testing.T) *Store {
	c := businessConfig(testConfig(t))
	c.Devices = nil
	c.Business.Principals[0].LegacyUsers = nil
	s, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func runBusiness(t *testing.T, s *Store, op string, c users.Command) users.Result {
	t.Helper()
	r, e := s.Business(context.Background(), s.Config.Business.Principals[0], op, c)
	if e != nil {
		t.Fatal(op, e)
	}
	return r
}
func bindBusiness(t *testing.T, s *Store, external string) (users.Command, users.Result) {
	t.Helper()
	c := users.Command{Service: "test", RequestID: "map-" + external, ExternalUser: external}
	u := runBusiness(t, s, "users", c)
	c.Account = u.Account
	c.Device = "device-" + external
	c.IdentityKey = strings.Repeat("01", 32)
	c.RequestID = "bind-" + external
	return c, runBusiness(t, s, "devices", c)
}
func issueBusiness(t *testing.T, s *Store, c users.Command) users.Result {
	c.RequestID = "issue-" + c.ExternalUser
	c.IdentityKey = ""
	c.TTLSeconds = 60
	return runBusiness(t, s, "credentials", c)
}
func TestBusinessConcurrentReplayAuthorizationAndRestart(t *testing.T) {
	s := freshBusiness(t)
	ctx := context.Background()
	p := s.Config.Business.Principals[0]
	c := users.Command{Service: "test", RequestID: "map", ExternalUser: "buyer"}
	var wg sync.WaitGroup
	out := make(chan users.Result, 24)
	errs := make(chan error, 24)
	for range 24 {
		wg.Go(func() { r, e := s.Business(ctx, p, "users", c); out <- r; errs <- e })
	}
	wg.Wait()
	close(out)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first users.Result
	for r := range out {
		if first.Account != "" && !reflect.DeepEqual(first, r) {
			t.Fatal("replay changed")
		}
		first = r
	}
	c.ExternalUser = "another"
	_, e := s.Business(ctx, p, "users", c)
	requireCode(t, e, "idempotency_conflict")
	c.ExternalUser = "buyer"
	c.Account = first.Account
	c.Device = "a1"
	c.IdentityKey = strings.Repeat("01", 32)
	c.RequestID = "bind"
	b := runBusiness(t, s, "devices", c)
	if !b.Creator {
		t.Fatal("first slot")
	}
	changed := c
	changed.RequestID = "other-bind"
	changed.IdentityKey = strings.Repeat("02", 32)
	_, e = s.Business(ctx, p, "devices", changed)
	requireCode(t, e, "device_conflict")
	_, e = s.Business(ctx, s.Config.Business.Principals[1], "devices", c)
	requireCode(t, e, "forbidden")
	changed = c
	changed.RequestID = "wrong-user"
	changed.ExternalUser = "unmapped"
	_, e = s.Business(ctx, p, "devices", changed)
	requireCode(t, e, "forbidden")
	c.IdentityKey = ""
	c.TTLSeconds = 60
	c.RequestID = "credential"
	credential := runBusiness(t, s, "credentials", c)
	for range 8 {
		wg.Go(func() {
			r, e := s.Business(ctx, p, "credentials", c)
			if e != nil || !reflect.DeepEqual(r, credential) {
				t.Error("credential replay changed", e)
			}
		})
	}
	wg.Wait()
	index, _, e := s.AuthenticateDevice(ctx, credential.Token)
	if e != nil || index != 0 {
		t.Fatal(index, e)
	}
	other, e := Open(ctx, s.Config)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if r := runBusiness(t, other, "credentials", c); !reflect.DeepEqual(r, credential) {
		t.Fatal("restart changed token")
	}
	changed = c
	changed.Device = "b1"
	changed.RequestID = "wrong-device"
	_, e = s.Business(ctx, p, "credentials", changed)
	requireCode(t, e, "device_conflict")
	changed = c
	changed.Service = "other"
	_, e = s.Business(ctx, p, "credentials", changed)
	requireCode(t, e, "scope_mismatch")
	var persisted string
	if e = s.Pool.QueryRow(ctx, "SELECT string_agg(result::text,'') FROM business_requests").Scan(&persisted); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(persisted, credential.Token) || strings.Contains(persisted, "rimd_") {
		t.Fatal("credential stored in ledger")
	}
	c.RequestID = "revoke"
	c.TTLSeconds = 0
	c.CredentialID = credential.CredentialID
	r := runBusiness(t, s, "revocations", c)
	if !r.Revoked {
		t.Fatal("not revoked")
	}
	_, _, e = other.AuthenticateDevice(ctx, credential.Token)
	requireCode(t, e, "credential_revoked")
	c.RequestID = "credential"
	c.TTLSeconds = 60
	c.CredentialID = ""
	_, e = s.Business(ctx, p, "credentials", c)
	requireCode(t, e, "credential_revoked")
}
func TestBusinessExpiryRollbackAndRequestLimit(t *testing.T) {
	s := freshBusiness(t)
	ctx := context.Background()
	c, _ := bindBusiness(t, s, "buyer")
	p := s.Config.Business.Principals[0]
	c.IdentityKey = ""
	c.RequestID = "short"
	c.TTLSeconds = 1
	r := runBusiness(t, s, "credentials", c)
	time.Sleep(time.Until(*r.ExpiresAt) + 10*time.Millisecond)
	_, _, e := s.AuthenticateDevice(ctx, r.Token)
	requireCode(t, e, "credential_expired")
	_, e = s.Business(ctx, p, "credentials", c)
	requireCode(t, e, "credential_expired")
	c.RequestID = "cancelled"
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, e = s.Business(cancelled, p, "credentials", c)
	if e == nil {
		t.Fatal("cancel passed")
	}
	var count int
	if e = s.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM business_requests WHERE request_id='cancelled'").Scan(&count); e != nil || count != 0 {
		t.Fatal("cancel persisted", e)
	}
	lock, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	limited, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	c.RequestID = "wait-timeout"
	_, e = s.Business(limited, p, "credentials", c)
	stop()
	if e == nil {
		t.Fatal("database wait ignored timeout")
	}
	if e = lock.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM business_requests WHERE request_id='wait-timeout'").Scan(&count); e != nil || count != 0 {
		t.Fatal("uncommitted timeout persisted", e)
	}
	_, e = s.Pool.Exec(ctx, `CREATE FUNCTION reject_issue() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic failure'; END$$; CREATE TRIGGER fail_issue BEFORE INSERT ON business_requests FOR EACH ROW EXECUTE FUNCTION reject_issue();`)
	if e != nil {
		t.Fatal(e)
	}
	c.RequestID = "rollback"
	_, e = s.Business(ctx, p, "credentials", c)
	if e == nil {
		t.Fatal("failure hidden")
	}
	if e = s.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM device_credentials").Scan(&count); e != nil || count != 1 {
		t.Fatal("partial credential survived", e)
	}
	_, e = s.Pool.Exec(ctx, "DROP TRIGGER fail_issue ON business_requests")
	if e != nil {
		t.Fatal(e)
	}
	runBusiness(t, s, "credentials", c)
	_, e = s.Pool.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result) SELECT 'shop','limit-'||n,'synthetic','{}'::jsonb FROM generate_series(1,4096-(SELECT COUNT(*)::integer FROM business_requests)) n`)
	if e != nil {
		t.Fatal(e)
	}
	c.RequestID = "over-limit"
	_, e = s.Business(ctx, p, "credentials", c)
	requireCode(t, e, "request_limit")
	// 达限仍允许取得原映射，不通过删除旧去重记录换取容量。
	runBusiness(t, s, "users", users.Command{Service: "test", RequestID: "map-buyer", ExternalUser: "buyer"})
}

func TestLegacySameAccountFixedDevicesRemainSupported(t *testing.T) {
	c := testConfig(t)
	c.Devices[1].Account = c.Devices[0].Account
	s, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	session, e := s.Session(context.Background(), 0)
	if e != nil || session.Own.Scope.Account != session.Peer.Scope.Account || session.Own.Scope.Device == session.Peer.Scope.Device {
		t.Fatal("legacy pair changed", e)
	}
}
func TestLegacyUpgradeAdoptionPreservesMessages(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	ack, e := s.Accept(ctx, 0, send("retained"))
	if e != nil {
		t.Fatal(e)
	}
	c := businessConfig(s.Config)
	next, e := Open(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	cmd := users.Command{Service: "test", RequestID: "map", ExternalUser: "legacy_alice"}
	user := runBusiness(t, next, "users", cmd)
	if user.Account != "alice" {
		t.Fatal("legacy account changed")
	}
	cmd.Account = "alice"
	cmd.Device = "a1"
	cmd.IdentityKey = c.Devices[0].IdentityKey
	cmd.RequestID = "bind"
	runBusiness(t, next, "devices", cmd)
	credential := issueBusiness(t, next, cmd)
	index, _, e := next.AuthenticateDevice(ctx, credential.Token)
	if e != nil || index != 0 {
		t.Fatal(e)
	}
	again, e := next.Accept(ctx, 0, send("retained"))
	if e != nil || again != ack {
		t.Fatal("acceptance changed", e)
	}
	page, e := next.Page(ctx, 1, m.Poll{After: "0", Limit: 4})
	if e != nil || len(page.Events) != 1 {
		t.Fatal("mailbox lost", e)
	}
	if _, ok := next.Config.Authenticate(strings.Repeat("11", 32)); ok {
		t.Fatal("legacy credential enabled")
	}
	bad := next.Config
	bad.Business = nil
	unexpected, e := Open(ctx, bad)
	if unexpected != nil {
		unexpected.Close()
	}
	requireCode(t, e, "configuration_mismatch")
	var raw []byte
	if e = next.Pool.QueryRow(ctx, "SELECT result FROM business_requests WHERE request_id='map'").Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var result users.Result
	if json.Unmarshal(raw, &result) != nil || result.Account != "alice" {
		t.Fatal("ledger missing")
	}
}
