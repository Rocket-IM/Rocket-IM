package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"rocket-im/service/internal/users"
	"strings"
	"testing"
	"time"
)

func diagnosticStore(t *testing.T, guarded bool) (*Store, config.Config, users.Command, users.Result, [2]string) {
	t.Helper()
	c := businessConfig(testConfig(t))
	c.Devices = nil
	c.Business.Principals[0].LegacyUsers = nil
	tokens := [2]string{"rimb_" + strings.Repeat("a", 64), "rimb_" + strings.Repeat("b", 64)}
	for i, token := range tokens {
		h := sha256.Sum256([]byte(token))
		c.Business.Principals[i].TokenSHA256 = hex.EncodeToString(h[:])
	}
	c.Business.Principals[0].CapacityRead = true
	s := openOK(t, c)
	command, _ := bindBusiness(t, s, "diagnostic")
	credential := issueBusiness(t, s, command)
	if guarded {
		c = guardConfig(t, c)
		s.Close()
		maintainOK(t, c, "enroll", "")
		maintainOK(t, c, "enable-reconciliation", "")
		s = openOK(t, c)
	}
	return s, c, command, credential, tokens
}
func diagnosticBudget(t *testing.T, out m.Capacity, name string) m.CapacityBudget {
	t.Helper()
	for _, b := range out.Budgets {
		if b.Category == name {
			return b
		}
	}
	t.Fatal("missing budget", name)
	return m.CapacityBudget{}
}
func diagnosticBlock(t *testing.T, out m.Capacity, operation, reason string) {
	t.Helper()
	for _, o := range out.Operations {
		if o.Operation == operation {
			for _, r := range o.Blockers {
				if r == reason && o.State == "blocked" {
					return
				}
			}
		}
	}
	t.Fatal("missing blocker", operation, reason)
}

func TestDiagnosticsScopeAuthenticationExactMetersAndNoWrites(t *testing.T) {
	ctx := context.Background()
	for _, guarded := range []bool{false, true} {
		t.Run(map[bool]string{false: "schema4", true: "schema5"}[guarded], func(t *testing.T) {
			s, _, command, credential, tokens := diagnosticStore(t, guarded)
			before, e := s.readSnapshot(ctx)
			if e != nil {
				t.Fatal(e)
			}
			admin, e := s.CapacityBusiness(ctx, tokens[0])
			if e != nil {
				t.Fatal(e)
			}
			device, e := s.CapacityDevice(ctx, credential.Token)
			if e != nil {
				t.Fatal(e)
			}
			if len(device.Budgets) != 1 || device.Scope.Access != "device" || *device.Scope.Account != command.Account || device.Scope.Principal != nil || device.Cursors.Tail != "0" {
				t.Fatal("device scope leaked", device)
			}
			if admin.Scope.Access != "service" || admin.Cursors != nil || admin.Scope.Account != nil || *admin.Scope.Principal != "shop" {
				t.Fatal("global scope invalid")
			}
			if *diagnosticBudget(t, admin, "business_requests").Used != "3" {
				t.Fatal("wrong business count")
			}
			var rowBytes int64
			for _, table := range before.Tables {
				for _, row := range table.Rows {
					rowBytes += int64(len(row))
				}
			}
			wantRows := capacityBudget("reconciliation_row_bytes", "bytes", rowBytes, evidenceLimit)
			wantExport := "not_applied"
			if !guarded {
				wantRows.Enforcement = "not_applied"
				wantExport = "precheck"
			}
			if !reflect.DeepEqual(diagnosticBudget(t, admin, "reconciliation_row_bytes"), wantRows) || diagnosticBudget(t, admin, "export_row_bytes").Enforcement != wantExport {
				t.Fatal("row accounting drift")
			}
			if guarded {
				raw, _ := json.Marshal(makeServiceBackup(before, s.maintenance.state))
				if *diagnosticBudget(t, admin, "export_file_bytes").Used != *capacityBudget("x", "bytes", int64(len(raw)), backupLimit).Used {
					t.Fatal("file encoding drift")
				}
			}
			_, e = s.CapacityBusiness(ctx, tokens[1])
			requireCode(t, e, "forbidden")
			_, e = s.CapacityBusiness(ctx, credential.Token)
			requireCode(t, e, "unauthorized")
			_, e = s.CapacityDevice(ctx, tokens[0])
			requireCode(t, e, "unauthorized")
			after, e := s.readSnapshot(ctx)
			if e != nil || digestJSON(before) != digestJSON(after) {
				t.Fatal("diagnosis mutated original", e)
			}
			raw, _ := json.Marshal(admin)
			for _, secret := range []string{credential.Token, credential.CredentialID, "identity_key", "external_user", "snapshot", "database_url", s.Config.RecoveryState} {
				if secret != "" && strings.Contains(string(raw), secret) {
					t.Fatal("secret or internal row leaked")
				}
			}
			command.IdentityKey = ""
			command.CredentialID = credential.CredentialID
			command.RequestID = "revoke-diagnostic"
			runBusiness(t, s, "revocations", command)
			_, e = s.CapacityDevice(ctx, credential.Token)
			requireCode(t, e, "credential_revoked")
			command.RequestID = "expire-diagnostic"
			command.CredentialID = ""
			command.TTLSeconds = 1
			expiring := runBusiness(t, s, "credentials", command)
			time.Sleep(max(time.Until(*expiring.ExpiresAt)+time.Millisecond, 0))
			_, e = s.CapacityDevice(ctx, expiring.Token)
			requireCode(t, e, "credential_expired")
			if guarded {
				sealClose(t, s)
			}
		})
	}
}

func TestDiagnosticsFullLedgerDoesNotConsumeCapacity(t *testing.T) {
	ctx := context.Background()
	s, _, _, credential, tokens := diagnosticStore(t, true)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result) SELECT 'fixture','diagnostic-'||n,'synthetic','{}'::jsonb FROM generate_series(1,4096-(SELECT COUNT(*)::integer FROM business_requests)) n`)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	before, e := s.readSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for range 3 {
		out, e := s.CapacityBusiness(ctx, tokens[0])
		if e != nil {
			t.Fatal(e)
		}
		if *diagnosticBudget(t, out, "business_requests").Used != "4096" {
			t.Fatal("full count lost")
		}
		diagnosticBlock(t, out, "renew_credential", "request_limit")
		diagnosticBlock(t, out, "revoke_credential", "request_limit")
		if _, e = s.CapacityDevice(ctx, credential.Token); e != nil {
			t.Fatal(e)
		}
	}
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("read consumed full ledger", e)
	}
	sealClose(t, s)
}

func TestDiagnosticsWaitsForTransactionAndRejectsUnknownEvidence(t *testing.T) {
	ctx := context.Background()
	s, c, _, credential, tokens := diagnosticStore(t, true)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "UPDATE alpha_conversation SET welcome='diagnostic-unconfirmed'"); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := s.CapacityBusiness(ctx, tokens[0]); done <- e }()
	select {
	case e := <-done:
		t.Fatal("read escaped transaction gate", e)
	case <-time.After(20 * time.Millisecond):
	}
	w := tx.(*evidencedTransaction)
	w.Tx = uncertainCommit{w.Tx}
	requireCode(t, tx.Commit(ctx), "service_reconciliation_required")
	requireCode(t, <-done, "service_reconciliation_required")
	out, e := s.CapacityDevice(ctx, credential.Token)
	requireCode(t, e, "service_reconciliation_required")
	if out.Version != "" {
		t.Fatal("failed access leaked diagnosis")
	}
	s.Close()
	maintainOK(t, c, "reconcile", "")
	next := openOK(t, c)
	if _, e = next.CapacityBusiness(ctx, tokens[0]); e != nil {
		t.Fatal(e)
	}
	sealClose(t, next)
}

func TestDiagnosticsApprovedClosedContextAndOldRetry(t *testing.T) {
	ctx := context.Background()
	f := recoveryStore(t)
	original, e := f.s.Accept(ctx, 0, send("prior"))
	if e != nil {
		t.Fatal(e)
	}
	round := f.offer(t)
	id := *round.Context
	f.publish(t, 1, "approval", m.RecoveryBody{Kind: "approval", Context: id, Welcome: "aabb"})
	f.publish(t, 1, "close_peer", m.RecoveryBody{Kind: "close", Context: id})
	f.publish(t, 0, "close_target", m.RecoveryBody{Kind: "close", Context: id})
	tx, e := f.s.beginRead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	out, e := f.s.capacityBase(ctx, tx)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if out.Recovery != "closed" {
		t.Fatal(out.Recovery)
	}
	diagnosticBlock(t, out, "new_send", "context_not_accepted")
	_, e = f.s.Accept(ctx, 0, send("blocked"))
	requireCode(t, e, "context_not_accepted")
	retry, e := f.s.Accept(ctx, 0, send("prior"))
	if e != nil || retry != original {
		t.Fatal("old retry lost", e)
	}
}

func TestDiagnosticsConfigurationDefaultAndBackupEncoding(t *testing.T) {
	s, c, _, _, tokens := diagnosticStore(t, true)
	ctx := context.Background()
	out, e := s.CapacityBusiness(ctx, tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	size := diagnosticBudget(t, out, "export_file_bytes")
	if size.Used == nil {
		t.Fatal(size)
	}
	sealClose(t, s)
	backup := c.RecoveryState + ".backup"
	maintainOK(t, c, "backup", backup)
	raw, e := os.ReadFile(backup)
	if e != nil {
		t.Fatal(e)
	}
	// seal更新固定宽度的摘要/检查点；完整文件长度必须与运行期编码观察一致。
	expected := capacityBudget("export_file_bytes", "bytes", int64(len(raw)), backupLimit)
	if *size.Used != *expected.Used {
		t.Fatal("export size mismatch", *size.Used, *expected.Used)
	}
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	maintainOK(t, target, "restore", backup)
	next := openOK(t, target)
	if _, e = next.CapacityBusiness(ctx, tokens[0]); e != nil {
		t.Fatal(e)
	}
	sealClose(t, next)
	c.Business.Principals[0].CapacityRead = false
	encoded, _ := json.Marshal(c.Business)
	if strings.Contains(string(encoded), "capacity_read") {
		t.Fatal("default changed legacy JSON")
	}
	_, e = Open(ctx, targetWithConfig(target, c))
	requireCode(t, e, "maintenance_configuration_mismatch")
}
func targetWithConfig(target, changed config.Config) config.Config {
	target.Business = changed.Business
	return target
}
