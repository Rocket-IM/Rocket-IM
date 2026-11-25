package storage

import (
	"context"
	"fmt"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/users"
	"testing"
	"time"
)

// 内部4096账本填充与真实签发/到期/撤销入口；不是4096次联网续期。
func TestBudgetFullLedgerBlocksRenewalAndNewRevocation(t *testing.T) {
	ctx := context.Background()
	s := freshBusiness(t)
	command, _ := bindBusiness(t, s, "budget-buyer")
	valid := issueBusiness(t, s, command)
	command.IdentityKey = ""
	command.RequestID = "budget-expiring"
	command.TTLSeconds = 1
	expiring := runBusiness(t, s, "credentials", command)
	revocation := users.Command{Service: "test", RequestID: "budget-revoke", ExternalUser: command.ExternalUser, Account: command.Account, Device: command.Device, CredentialID: valid.CredentialID}
	tx, err := s.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result)
	 SELECT 'shop','budget-fixture-'||n,'synthetic','{}'::jsonb
	 FROM generate_series(1,4096-(SELECT COUNT(*)::integer FROM business_requests)) n`)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// 到期真实经过时间；没有改时钟、令牌或数据库截止。
	time.Sleep(max(time.Until(*expiring.ExpiresAt)+10*time.Millisecond, 0))
	read := func() string {
		t.Helper()
		tx, e := s.beginRead(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		var facts string
		e = tx.QueryRow(ctx, `SELECT jsonb_build_array(
		 (SELECT count(*) FROM business_requests),
		 (SELECT jsonb_agg(to_jsonb(c) ORDER BY credential_id) FROM device_credentials c))::text`).Scan(&facts)
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		return facts
	}
	before := read()
	_, err = s.Business(ctx, s.Config.Business.Principals[0], "revocations", revocation)
	requireCode(t, err, "request_limit")
	_, _, err = s.AuthenticateDevice(ctx, valid.Token)
	if err != nil {
		t.Fatal("failed revocation changed still-valid credential", err)
	}
	_, _, err = s.AuthenticateDevice(ctx, expiring.Token)
	requireCode(t, err, "credential_expired")
	_, err = s.Business(ctx, s.Config.Business.Principals[0], "credentials", command)
	requireCode(t, err, "credential_expired")
	command.RequestID = "budget-renew"
	_, err = s.Business(ctx, s.Config.Business.Principals[0], "credentials", command)
	requireCode(t, err, "request_limit")
	if before != read() {
		t.Fatal("rejected maintenance consumed facts or revived credentials")
	}
	t.Log("4096 requests preserved; new renewal/revocation blocked; expired retry stays expired")
}

// 真实签名、预约和双方关闭；假KeyPackage只验证Service账本，不声称MLS后继互通。
func TestBudgetSixteenClosedRoundsPreserveOriginalReservations(t *testing.T) {
	f := recoveryStore(t)
	ctx := context.Background()
	original := f.q
	var first *m.RecoveryRound
	for i := 0; i < 16; i++ {
		f.q.ID = fmt.Sprintf("budget-round-%d", i)
		round := f.offer(t)
		if i == 0 {
			original = f.q
		}
		context := *round.Context
		f.publish(t, 1, "close_peer", m.RecoveryBody{Kind: "close", Context: context})
		round = f.publish(t, 0, "close_target", m.RecoveryBody{Kind: "close", Context: context})
		if round.Status != "closed" {
			t.Fatal(round.Status)
		}
		if i == 0 {
			first = round
		}
		f.q.Previous = &context
	}
	before, err := f.s.readSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.q.ID = "budget-round-overflow"
	_, err = f.s.ReserveRecovery(ctx, 0, f.q)
	requireCode(t, err, "recovery_limit")
	again, err := f.s.ReserveRecovery(ctx, 0, original)
	if err != nil || !m.Equal(first, again) {
		t.Fatal("full round ledger lost original", err)
	}
	after, err := f.s.readSnapshot(ctx)
	if err != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("full round ledger changed", err)
	}
	t.Log("16 signed closed rounds retained; seventeenth rejected; exact first reservation preserved")
}
