package storage

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"os/exec"
	"rocket-im/service/internal/config"
	"strings"
	"testing"
)

type evidenceCrashInput struct {
	Config config.Config
	Window string
}
type exitAtCommit struct{ pgx.Tx }

func (tx exitAtCommit) Commit(ctx context.Context) error {
	if e := tx.Tx.Commit(ctx); e != nil {
		return e
	}
	os.Exit(86)
	return nil
}

func crashEvidence(t *testing.T, c config.Config, window string) {
	t.Helper()
	path := c.RecoveryState + ".child"
	data, e := json.Marshal(evidenceCrashInput{c, window})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestReconciliationProcessHelper$")
	cmd.Env = append(os.Environ(), "ROCKET_IM_TEST_RECONCILIATION_CHILD="+path)
	output, e := cmd.CombinedOutput()
	status, ok := e.(*exec.ExitError)
	if !ok || status.ExitCode() != 86 {
		t.Fatalf("window %s failed: %s", window, output)
	}
}

// 仅测试程序拥有退出控制；使用真实PG事务、原证据写入和原业务提交封装。
func TestReconciliationProcessHelper(t *testing.T) {
	path := os.Getenv("ROCKET_IM_TEST_RECONCILIATION_CHILD")
	if path == "" {
		t.Skip("only child fixture")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var input evidenceCrashInput
	if e = json.Unmarshal(data, &input); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if strings.HasPrefix(input.Window, "start_") || strings.HasPrefix(input.Window, "enable_") {
		s, e := connect(ctx, input.Config)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.acquireMaintenance(ctx, false); e != nil {
			t.Fatal(e)
		}
		if _, e = s.verifySealed(ctx); e != nil {
			t.Fatal(e)
		}
		tx, e := s.Pool.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		st := s.maintenance.state
		run, e := randomCheckpoint()
		if e != nil {
			t.Fatal(e)
		}
		if strings.HasPrefix(input.Window, "enable_") {
			if e = applyMigration(ctx, tx, "005_service_reconciliation.sql"); e != nil {
				t.Fatal(e)
			}
			st.Version, st.Phase = reconciliationVersion, "upgrading"
			st.Evidence = &reconciliationEvidence{RunID: run}
		} else {
			st.Phase = "running"
		}
		if e = s.reserveEvidence(ctx, tx, st, run); e != nil {
			t.Fatal(e)
		}
		if strings.HasSuffix(input.Window, "committed") {
			if e = tx.Commit(ctx); e != nil {
				t.Fatal(e)
			}
		}
		os.Exit(86)
	}
	if input.Window == "reconcile_checked" {
		s, e := connect(ctx, input.Config)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.acquireMaintenance(ctx, false); e != nil {
			t.Fatal(e)
		}
		data, e := s.readSnapshot(ctx)
		if e != nil || digestJSON(data) != s.maintenance.state.Digest {
			t.Fatal("candidate mismatch", e)
		}
		os.Exit(86)
	}
	if input.Window == "reconcile_completed" {
		maintainOK(t, input.Config, "reconcile", "")
		os.Exit(86)
	}
	s := openOK(t, input.Config)
	if input.Window == "started" {
		os.Exit(86)
	}
	tx, e := s.begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "UPDATE alpha_conversation SET welcome='aaff'"); e != nil {
		t.Fatal(e)
	}
	w := tx.(*evidencedTransaction)
	switch input.Window {
	case "before_reservation":
		os.Exit(86)
	case "reserved":
		if e = s.reserveEvidence(ctx, w.Tx, s.maintenance.state, s.maintenance.state.Evidence.RunID); e != nil {
			t.Fatal(e)
		}
		os.Exit(86)
	case "committed":
		w.Tx = exitAtCommit{w.Tx}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	os.Exit(86)
}

func TestReconciliationProcessWindows(t *testing.T) {
	ctx := context.Background()
	for _, window := range []string{"started", "start_reserved", "start_committed", "enable_reserved", "enable_committed", "before_reservation", "reserved", "committed", "completed", "reconcile_checked", "reconcile_completed"} {
		t.Run(window, func(t *testing.T) {
			s, c := evidenceStore(t)
			if strings.HasPrefix(window, "enable_") {
				sealClose(t, s)
				original := testStore(t)
				c = guardConfig(t, original.Config)
				original.Close()
				maintainOK(t, c, "enroll", "")
			} else if window == "reconcile_checked" || window == "reconcile_completed" {
				s.Close()
			} else {
				sealClose(t, s)
			}
			crashEvidence(t, c, window)
			var st maintenanceState
			if e := readPrivate(c.RecoveryState, 65536, &st); e != nil {
				t.Fatal(e)
			}
			if window == "reserved" || window == "start_reserved" || window == "enable_reserved" {
				if st.Evidence.Pending == nil {
					t.Fatal("lost pending evidence")
				}
				_, e := Maintain(ctx, c, "reconcile", "")
				requireCode(t, e, "service_reconciliation_incomplete")
				_, e = Open(ctx, c)
				requireCode(t, e, "service_reconciliation_required")
				return
			}
			if window == "committed" && st.Evidence.Pending == nil {
				t.Fatal("commit window lost pending record")
			}
			maintainOK(t, c, "reconcile", "")
			next := openOK(t, c)
			value, e := next.Welcome(ctx, 0, nil)
			if e != nil {
				t.Fatal(e)
			}
			want := "ccdd"
			if window == "committed" || window == "completed" {
				want = "aaff"
			}
			if value.Welcome != want {
				t.Fatal("wrong recovered candidate", value)
			}
			sealClose(t, next)
		})
	}
}
