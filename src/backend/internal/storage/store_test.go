package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"os"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T) config.Config {
	t.Helper()
	dsn := os.Getenv("ROCKET_IM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("explicit local PostgreSQL required")
	}
	ctx := context.Background()
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := fmt.Sprintf("alpha_test_%d", time.Now().UnixNano())
	if _, e = p.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = p.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); p.Close() })
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	c := config.Config{Service: "test", Conversation: "chat", DatabaseURL: u.String(), Devices: []config.Device{{Account: "alice", Device: "a1", IdentityKey: strings.Repeat("01", 32), TokenSHA256: strings.Repeat("11", 32)}, {Account: "bob", Device: "b1", IdentityKey: strings.Repeat("02", 32), TokenSHA256: strings.Repeat("22", 32)}}}
	return c
}
func testStore(t *testing.T) *Store {
	t.Helper()
	c := testConfig(t)
	ctx := context.Background()
	s, e := Open(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	if _, e = s.Material(ctx, 1, &m.Material{Identity: c.Identity(1), KeyPackage: "aabb"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Welcome(ctx, 0, &m.Welcome{Welcome: "ccdd"}); e != nil {
		t.Fatal(e)
	}
	return s
}
func send(id string) m.Send {
	return m.Send{RequestID: "request-" + id, Envelope: m.Envelope{Service: "test", Conversation: "chat", SenderAccount: "alice", SenderDevice: "a1", MessageID: id, Context: "initial", Ciphertext: "abcd"}}
}
func requireCode(t *testing.T, e error, code string) {
	t.Helper()
	if e == nil || m.ErrorCode(e) != code {
		t.Fatalf("expected %s got %v", code, e)
	}
}
func TestConcurrentExactRetryAndConflict(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan m.Acceptance, 32)
	failures := make(chan error, 32)
	for range 32 {
		wg.Go(func() {
			ack, e := s.Accept(ctx, 0, send("one"))
			if e != nil {
				failures <- e
			} else {
				results <- ack
			}
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		t.Fatal(e)
	}
	var expected m.Acceptance
	for ack := range results {
		if expected.Sequence != "" && ack != expected {
			t.Fatal("retry changed acceptance")
		}
		expected = ack
	}
	if expected.Sequence != "1" {
		t.Fatal(expected)
	}
	changed := send("one")
	changed.Envelope.Ciphertext = "abce"
	_, e := s.Accept(ctx, 0, changed)
	requireCode(t, e, "idempotency_conflict")
	changed = send("two")
	changed.RequestID = "request-one"
	_, e = s.Accept(ctx, 0, changed)
	requireCode(t, e, "idempotency_conflict")
	page, e := s.Page(ctx, 1, m.Poll{After: "0", Limit: 4})
	if e != nil || len(page.Events) != 1 || page.Upper != "1" {
		t.Fatalf("%+v %v", page, e)
	}
}
func TestCommitOrderingStablePagesAndRollback(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// 未提交的分配对补拉不可见；另一发送须等待本事务，回滚不产生缺口。
	if e = s.append(ctx, tx, 1, m.Event{Kind: "message", Acceptance: m.Acceptance{Sequence: "99"}}); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := s.Accept(ctx, 0, send("first")); done <- e }()
	page, e := s.Page(ctx, 1, m.Poll{After: "0", Limit: 2})
	if e != nil || page.Upper != "0" {
		t.Fatalf("uncommitted leaked: %+v %v", page, e)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	for _, id := range []string{"second", "third", "fourth"} {
		if _, e = s.Accept(ctx, 0, send(id)); e != nil {
			t.Fatal(e)
		}
	}
	first, e := s.Page(ctx, 1, m.Poll{After: "0", Limit: 2})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Accept(ctx, 0, send("fifth")); e != nil {
		t.Fatal(e)
	}
	second, e := s.Page(ctx, 1, m.Poll{After: first.Next, Upper: &first.Upper, Limit: 2})
	if e != nil || second.Next != "4" || second.Upper != "4" {
		t.Fatalf("%+v %v", second, e)
	}
	last, e := s.Page(ctx, 1, m.Poll{After: second.Next, Limit: 2})
	if e != nil || len(last.Events) != 1 || last.Next != "5" {
		t.Fatal(last, e)
	}
	for i, event := range append(first.Events, second.Events...) {
		if event.Sequence != fmt.Sprint(i+1) {
			t.Fatal("gap")
		}
	}
	again, e := Open(ctx, s.Config)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	ack, e := again.Accept(ctx, 0, send("first"))
	if e != nil || ack.Sequence != "1" {
		t.Fatal(ack, e)
	}
}
func TestParallelDistinctMessagesAndReceiptAtomicity(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	out := make(chan int, 20)
	fail := make(chan error, 20)
	for i := range 20 {
		wg.Go(func() {
			ack, e := s.Accept(ctx, 0, send(fmt.Sprint(i)))
			if e != nil {
				fail <- e
				return
			}
			n, _ := m.Number(ack.Sequence)
			out <- int(n)
		})
	}
	wg.Wait()
	close(fail)
	close(out)
	for e := range fail {
		t.Fatal(e)
	}
	ids := []int{}
	for n := range out {
		ids = append(ids, n)
	}
	sort.Ints(ids)
	for i, n := range ids {
		if n != i+1 {
			t.Fatal(ids)
		}
	}
	// 真实PG触发器令回执事务中途失败，验证不留下处理游标和已送达标记。
	_, e := s.Pool.Exec(ctx, `CREATE FUNCTION reject_receipt() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.device_index=0 THEN RAISE EXCEPTION 'test commit failure'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_receipt BEFORE INSERT ON alpha_mailbox FOR EACH ROW EXECUTE FUNCTION reject_receipt();`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Processed(ctx, 1, m.Processed{Sequence: "1"}); e == nil {
		t.Fatal("expected transaction failure")
	}
	var processed int
	var delivered bool
	if e = s.Pool.QueryRow(ctx, "SELECT processed FROM alpha_devices WHERE device_index=1").Scan(&processed); e != nil {
		t.Fatal(e)
	}
	if e = s.Pool.QueryRow(ctx, "SELECT delivered FROM alpha_messages WHERE accepted=1").Scan(&delivered); e != nil {
		t.Fatal(e)
	}
	if processed != 0 || delivered {
		t.Fatal("uncommitted receipt escaped")
	}
	if _, e = s.Pool.Exec(ctx, "DROP TRIGGER fail_receipt ON alpha_mailbox"); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = s.Processed(ctx, 1, m.Processed{Sequence: "1"}); e != nil {
			t.Fatal(e)
		}
	}
	page, e := s.Page(ctx, 0, m.Poll{After: "0", Limit: 4})
	if e != nil || len(page.Events) != 1 || page.Events[0].Kind != "delivered" {
		t.Fatal(page, e)
	}
	_, e = s.Processed(ctx, 1, m.Processed{Sequence: "3"})
	requireCode(t, e, "invalid_cursor")
}
func TestScopeMaterialAndSecretBoundaries(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, mutate := range []func(*m.Send){func(v *m.Send) { v.Envelope.Service = "other" }, func(v *m.Send) { v.Envelope.Conversation = "other" }, func(v *m.Send) { v.Envelope.SenderAccount = "bob" }, func(v *m.Send) { v.Envelope.SenderDevice = "other" }} {
		v := send("x")
		mutate(&v)
		_, e := s.Accept(ctx, 0, v)
		requireCode(t, e, "scope_mismatch")
	}
	_, e := s.Accept(ctx, 1, send("x"))
	requireCode(t, e, "scope_mismatch")
	_, e = s.Material(ctx, 0, &m.Material{Identity: s.Config.Identity(1), KeyPackage: "abcd"})
	requireCode(t, e, "identity_mismatch")
	_, e = s.Welcome(ctx, 1, &m.Welcome{Welcome: "abcd"})
	requireCode(t, e, "forbidden")
	_, e = s.Page(ctx, 1, m.Poll{After: "9007199254740993", Limit: 4})
	requireCode(t, e, "invalid_cursor")
	_, e = s.Page(ctx, 1, m.Poll{After: "00", Limit: 4})
	requireCode(t, e, "invalid_cursor")
	raw, _ := json.Marshal(send("x"))
	var input m.Send
	if e = m.Decode(append(raw[:len(raw)-1], []byte(`,"text":"plaintext"}`)...), &input); e == nil {
		t.Fatal("plaintext field accepted")
	}
	changed := s.Config
	changed.Conversation = "different"
	other, e := Open(ctx, changed)
	if other != nil {
		other.Close()
	}
	requireCode(t, e, "configuration_mismatch")
}

func TestUnknownSchemaVersionFailsWithoutInstallingBinding(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, e := s.Pool.Exec(ctx, "ALTER TABLE schema_version DROP CONSTRAINT schema_version_version_check; UPDATE schema_version SET version=99"); e != nil {
		t.Fatal(e)
	}
	other, e := Open(ctx, s.Config)
	if other != nil {
		other.Close()
	}
	requireCode(t, e, "schema_version_unsupported")
	var count, version int
	if e = s.Pool.QueryRow(ctx, "SELECT COUNT(*),MAX(version) FROM schema_version").Scan(&count, &version); e != nil {
		t.Fatal(e)
	}
	if count != 1 || version != 99 {
		t.Fatal("failed migration changed existing format")
	}
}
