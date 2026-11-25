package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"strings"
	"testing"
)

// 非E2EE内部填充；检查64MiB文件和256MiB对账是独立预算，不能冒充合法业务负载。
func TestDiagnosticsExportAndEvidenceBudgetsAreSeparate(t *testing.T) {
	ctx := context.Background()
	s, c, _, _, tokens := diagnosticStore(t, true)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result) SELECT 'fixture','large-'||n,'synthetic',jsonb_build_object('padding',repeat('x',262144)) FROM generate_series(1,260) n`)
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
	out, e := s.CapacityBusiness(ctx, tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	file := diagnosticBudget(t, out, "export_file_bytes")
	row := diagnosticBudget(t, out, "export_row_bytes")
	evidence := diagnosticBudget(t, out, "reconciliation_row_bytes")
	if file.State != "measured" || *file.HardRemaining != "0" || *evidence.HardRemaining == "0" || row.Enforcement != "not_applied" {
		t.Fatal("budgets conflated")
	}
	raw, _ := json.Marshal(makeServiceBackup(before, s.maintenance.state))
	if *file.Used != *capacityBudget("export_file_bytes", "bytes", int64(len(raw)), backupLimit).Used {
		t.Fatal("actual encoding mismatch")
	}
	diagnosticBlock(t, out, "export", "export_file_limit")
	after, e := s.readSnapshot(ctx)
	if e != nil || digestJSON(before) != digestJSON(after) {
		t.Fatal("diagnosis changed rows", e)
	}
	sealClose(t, s)
	_, e = Maintain(ctx, c, "backup", c.RecoveryState+".overlimit")
	requireCode(t, e, "maintenance_size_limit")
}

func TestDiagnosticsBeyondEvidenceLimitReportsExactRowsAndUnavailableFile(t *testing.T) {
	ctx := context.Background()
	s, _, _, _, tokens := diagnosticStore(t, false)
	// schema4未登记夹具故意超过运行对账预算，只验证有界诊断不返回部分总量。
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, `INSERT INTO business_requests(principal,request_id,request_hash,result) SELECT 'fixture','oversize-'||n,'synthetic',jsonb_build_object('padding',repeat('x',262144)) FROM generate_series(1,1025) n`)
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	out, e := s.CapacityBusiness(ctx, tokens[0])
	if e != nil {
		t.Fatal(e)
	}
	row := diagnosticBudget(t, out, "reconciliation_row_bytes")
	file := diagnosticBudget(t, out, "export_file_bytes")
	if *row.HardRemaining != "0" || row.Enforcement != "not_applied" || file.State != "unavailable" || file.Used != nil || file.HardRemaining != nil || *file.Reason != "reconciliation_size_limit" {
		t.Fatal("partial or invented full measurement")
	}
	diagnosticBlock(t, out, "export", "reconciliation_size_limit")
}

func TestDiagnosticsSixteenRoundsRetainUsageAndOriginals(t *testing.T) {
	token := "rimb_" + strings.Repeat("c", 64)
	f := recoveryStoreConfig(t, func(c config.Config) config.Config {
		c = businessConfig(c)
		h := sha256.Sum256([]byte(token))
		c.Business.Principals[0].TokenSHA256 = hex.EncodeToString(h[:])
		c.Business.Principals[0].CapacityRead = true
		return c
	})
	ctx := context.Background()
	for i := 0; i < 16; i++ {
		f.q.ID = "diagnostic-round-" + string(rune('a'+i))
		r := f.offer(t)
		context := *r.Context
		f.publish(t, 1, "close_peer", m.RecoveryBody{Kind: "close", Context: context})
		f.publish(t, 0, "close_target", m.RecoveryBody{Kind: "close", Context: context})
		f.q.Previous = &context
	}
	tx, e := f.s.beginRead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	count, size, e := f.s.recoveryUsage(ctx, tx)
	if e != nil || count != 16 || size <= 0 {
		t.Fatal(count, size, e)
	}
	// 与诊断同源的计量必须等于PG record文本字节，不用字符数或全表大小替代。
	var exact int64
	if e = tx.QueryRow(ctx, "SELECT SUM(octet_length(record::text)) FROM alpha_recovery").Scan(&exact); e != nil || exact != size {
		t.Fatal("recovery byte count", e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	out, e := f.s.CapacityBusiness(ctx, token)
	if e != nil {
		t.Fatal(e)
	}
	if *diagnosticBudget(t, out, "recovery_rounds").Used != "16" {
		t.Fatal("round observation lost")
	}
	diagnosticBlock(t, out, "new_recovery", "recovery_limit")
	f.q.ID = "diagnostic-overflow"
	_, e = f.s.ReserveRecovery(ctx, 0, f.q)
	requireCode(t, e, "recovery_limit")
}
