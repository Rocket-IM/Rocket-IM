package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"os/exec"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"testing"
)

type worksetCrash struct {
	Config            config.Config
	Workset           m.CapacityWorkset
	Operation, Window string
}
type worksetExitBeforeCommit struct{ pgx.Tx }

func (tx worksetExitBeforeCommit) Commit(context.Context) error { os.Exit(86); return nil }

// 只在测试程序替换提交边界。实际原件核验、事务写入、容量与外部进度仍为生产入口。
func TestWorksetProcessHelper(t *testing.T) {
	path := os.Getenv("ROCKET_IM_TEST_WORKSET_CHILD")
	if path == "" {
		t.Skip("only child fixture")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var input worksetCrash
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("invalid child input")
	}
	ctx := context.Background()
	s := openOK(t, input.Config)
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	wrapped := tx.(*evidencedTransaction)
	if input.Window == "before_external_reserve" {
		tx = worksetExitBeforeCommit{tx}
	}
	if input.Window == "before_sql_commit" {
		wrapped.Tx = worksetExitBeforeCommit{wrapped.Tx}
	}
	if input.Window == "after_sql_commit" {
		wrapped.Tx = exitAtCommit{wrapped.Tx}
	}
	if _, e = s.capacityWorkset(ctx, tx, worksetToken, input.Operation, &input.Workset); e != nil {
		t.Fatal(e)
	}
	os.Exit(86)
}
func TestWorksetProcessEveryPersistentBoundary(t *testing.T) {
	for _, operation := range []string{"prepare", "confirm", "settle"} {
		for _, window := range []string{"before_external_reserve", "before_sql_commit", "after_sql_commit", "after_external_confirm"} {
			t.Run(operation+"_"+window, func(t *testing.T) {
				s := worksetStore(t)
				w := controlWorkset(t, s)
				ctx := context.Background()
				prior := ""
				if operation != "prepare" {
					worksetCall(t, s, "prepare", &w, "prepared")
					prior = "prepared"
				}
				if operation == "settle" {
					worksetCall(t, s, "confirm", &w, "confirmed")
					prior = "confirmed"
					if _, e := s.Processed(ctx, 0, m.Processed{Sequence: "1", Disposition: "received"}); e != nil {
						t.Fatal(e)
					}
				}
				before, e := s.readSnapshot(ctx)
				if e != nil {
					t.Fatal(e)
				}
				c := s.Config
				sealClose(t, s)
				path := c.RecoveryState + ".workset-child"
				raw, e := json.Marshal(worksetCrash{c, w, operation, window})
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
				cmd := exec.Command(os.Args[0], "-test.run=^TestWorksetProcessHelper$")
				cmd.Env = append(os.Environ(), "ROCKET_IM_TEST_WORKSET_CHILD="+path)
				output, e := cmd.CombinedOutput()
				status, ok := e.(*exec.ExitError)
				if !ok || status.ExitCode() != 86 {
					t.Fatalf("child failed: %s", output)
				}
				_, e = Open(ctx, c)
				requireCode(t, e, "service_reconciliation_required")
				if window == "before_sql_commit" {
					// 外部候选存在但PG仍为前态，不能证明从未提交或未被回滚替换。
					// 保留原业务承诺及未决证据，禁止通过清除pending恢复可用性。
					var head maintenanceState
					if e = readPrivate(c.RecoveryState, 65536, &head); e != nil || head.Evidence.Pending == nil {
						t.Fatal("missing pending promise", e)
					}
					_, e = Maintain(ctx, c, "reconcile", "")
					requireCode(t, e, "service_reconciliation_incomplete")
					var retained maintenanceState
					if e = readPrivate(c.RecoveryState, 65536, &retained); e != nil || digestJSON(head) != digestJSON(retained) {
						t.Fatal("discarded unresolved evidence", e)
					}
					conn, err := pgx.Connect(ctx, c.DatabaseURL)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close(ctx)
					check, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
					if err != nil {
						t.Fatal(err)
					}
					defer check.Rollback(ctx)
					actual, err := evidenceSnapshot(ctx, check)
					if err != nil {
						t.Fatal(err)
					}
					for i, table := range before.Tables {
						if table.Name != "service_maintenance" && digestJSON(table) != digestJSON(actual.Tables[i]) {
							t.Fatal("discarded prior promise or original", table.Name)
						}
					}
					if e = check.Commit(ctx); e != nil {
						t.Fatal(e)
					}
					return
				}
				maintainOK(t, c, "reconcile", "")
				s = openOK(t, c)
				want := map[string]string{"prepare": "prepared", "confirm": "confirmed", "settle": "settled"}[operation]
				if window == "before_external_reserve" {
					want = prior
				}
				out, e := s.CapacityWorkset(ctx, worksetToken, "query", nil)
				if e != nil || (want == "" && out != nil) || (want != "" && (out == nil || out.Phase != want)) {
					t.Fatal("lost exact phase", e)
				}
				after, e := s.readSnapshot(ctx)
				if e != nil {
					t.Fatal(e)
				}
				for i, table := range before.Tables {
					if table.Name != "alpha_devices" && table.Name != "service_maintenance" && digestJSON(table) != digestJSON(after.Tables[i]) {
						t.Fatal("original discarded", table.Name)
					}
				}
				worksetCall(t, s, operation, &w, map[string]string{"prepare": "prepared", "confirm": "confirmed", "settle": "settled"}[operation])
				sealClose(t, s)
			})
		}
	}
}
