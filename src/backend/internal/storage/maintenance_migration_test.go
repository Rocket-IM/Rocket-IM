package storage

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"testing"
)

type crashImportInput struct {
	Config config.Config
	Backup string
}

func crashAfterImport(t *testing.T, c config.Config, path string) {
	t.Helper()
	input := c.RecoveryState + ".test-input"
	raw, e := json.Marshal(crashImportInput{c, path})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(input, raw, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMaintenanceCommitExitHelper$")
	cmd.Env = append(os.Environ(), "ROCKET_IM_TEST_MAINTENANCE_CHILD="+input)
	out, e := cmd.CombinedOutput()
	status, ok := e.(*exec.ExitError)
	if !ok || status.ExitCode() != 86 {
		t.Fatalf("commit exit helper failed: %s", out)
	}
}

// 测试进程在真实PG事务提交后立即退出；生产程序没有对应环境变量或退出钩子。
func TestMaintenanceCommitExitHelper(t *testing.T) {
	path := os.Getenv("ROCKET_IM_TEST_MAINTENANCE_CHILD")
	if path == "" {
		t.Skip("only child fixture")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var input crashImportInput
	if e = json.Unmarshal(raw, &input); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	s, e := connect(ctx, input.Config)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.acquireMaintenance(ctx, false); e != nil {
		t.Fatal(e)
	}
	var backup serviceBackup
	if e = readPrivate(input.Backup, backupLimit, &backup); e != nil {
		t.Fatal(e)
	}
	st := s.maintenance.state
	st.Phase = "restoring"
	st.PendingTarget = s.maintenance.target
	if e = writePrivate(s.maintenance.path, st, true); e != nil {
		t.Fatal(e)
	}
	if e = s.importSnapshot(ctx, backup.Snapshot, st.Digest); e != nil {
		t.Fatal(e)
	}
	os.Exit(86)
}

func TestMaintenanceSchema3UpgradePreservesAcceptance(t *testing.T) {
	ctx := context.Background()
	c := guardConfig(t, testConfig(t))
	s, e := connect(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	for _, name := range []string{"001_alpha.sql", "002_business_identity.sql", "003_successor_recovery.sql"} {
		if e = applyMigration(ctx, tx, name); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec(ctx, s.queries["insert_binding"], c.Binding()); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, s.queries["insert_devices"]); e != nil {
		t.Fatal(e)
	}
	if e = s.seedIdentities(ctx, tx); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Material(ctx, 1, &m.Material{Identity: c.Identity(1), KeyPackage: "aabb"}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Welcome(ctx, 0, &m.Welcome{Welcome: "ccdd"}); e != nil {
		t.Fatal(e)
	}
	ack, e := s.Accept(ctx, 0, send("schema3"))
	if e != nil {
		t.Fatal(e)
	}
	page, e := s.Page(ctx, 1, m.Poll{After: "0", Limit: 4})
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	maintainOK(t, c, "enroll", "")
	next := openOK(t, c)
	again, e := next.Accept(ctx, 0, send("schema3"))
	if e != nil || again != ack {
		t.Fatal("upgrade changed acceptance", e)
	}
	after, e := next.Page(ctx, 1, m.Poll{After: "0", Limit: 4})
	if e != nil || digestJSON(after) != digestJSON(page) {
		t.Fatal("upgrade changed events", e)
	}
	sealClose(t, next)
	path := c.RecoveryState + ".backup"
	maintainOK(t, c, "backup", path)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	maintainOK(t, target, "restore", path)
	restored := openOK(t, target)
	again, e = restored.Accept(ctx, 0, send("schema3"))
	if e != nil || again != ack {
		t.Fatal("restore changed migrated acceptance", e)
	}
	sealClose(t, restored)
}
