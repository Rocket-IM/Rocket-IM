package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"rocket-im/service/internal/config"
	m "rocket-im/service/internal/messaging"
	"testing"
	"time"
)

func guardConfig(t *testing.T, c config.Config) config.Config {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "maintenance-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	c.TLSCert = filepath.Join(dir, "server.pem")
	c.TLSKey = filepath.Join(dir, "server.key")
	c.RecoveryState = filepath.Join(dir, "state.json")
	for path, data := range map[string][]byte{c.TLSCert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.TLSKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})} {
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return c
}
func maintenanceDatabase(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("ROCKET_IM_TEST_DATABASE_URL")
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("maintenance_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{name}.Sanitize()
	if _, e = p.Exec(ctx, "CREATE DATABASE "+quoted); e != nil {
		p.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, e := p.Exec(ctx, "DROP DATABASE "+quoted+" WITH (FORCE)")
		p.Close()
		if e != nil {
			t.Error(e)
		}
	})
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + name
	return u.String()
}

func maintainOK(t *testing.T, c config.Config, op, path string) MaintenanceResult {
	t.Helper()
	r, e := Maintain(context.Background(), c, op, path)
	if e != nil {
		t.Fatal(op, e)
	}
	return r
}
func openOK(t *testing.T, c config.Config) *Store {
	t.Helper()
	s, e := Open(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
func sealClose(t *testing.T, s *Store) {
	t.Helper()
	if e := s.Seal(context.Background()); e != nil {
		t.Fatal(e)
	}
	s.Close()
}

func TestMaintenanceExactRestoreAndStaleRejection(t *testing.T) {
	ctx := context.Background()
	original := testStore(t)
	c := guardConfig(t, original.Config)
	ack, e := original.Accept(ctx, 0, send("original"))
	if e != nil {
		t.Fatal(e)
	}
	original.Close()
	maintainOK(t, c, "enroll", "")
	old := filepath.Join(filepath.Dir(c.RecoveryState), "old.backup")
	maintainOK(t, c, "backup", old)
	_, e = Maintain(ctx, c, "restore", old)
	requireCode(t, e, "maintenance_target_not_new")
	s := openOK(t, c)
	if _, e = Maintain(ctx, c, "backup", old+".live"); e == nil {
		t.Fatal("live backup allowed")
	}
	ack2, e := s.Accept(ctx, 0, send("new"))
	if e != nil {
		t.Fatal(e)
	}
	for _, sequence := range []string{"1", "2"} {
		if _, e = s.Processed(ctx, 1, m.Processed{Sequence: sequence}); e != nil {
			t.Fatal(e)
		}
	}
	sealClose(t, s)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	_, e = Maintain(ctx, target, "restore", old)
	requireCode(t, e, "service_backup_stale")
	current := old + ".new"
	maintainOK(t, c, "backup", current)
	r := maintainOK(t, target, "restore", current)
	if again := maintainOK(t, target, "restore", current); again != r {
		t.Fatal("repeat changed checkpoint")
	}
	if _, e = Open(ctx, c); e == nil {
		t.Fatal("retired target reopened")
	} else {
		requireCode(t, e, "maintenance_target_mismatch")
	}
	restored := openOK(t, target)
	for _, prior := range []m.Acceptance{ack, ack2} {
		got, e := restored.Accept(ctx, 0, send(prior.MessageID))
		if e != nil || got != prior {
			t.Fatal("acceptance changed", e)
		}
	}
	page, e := restored.Page(ctx, 1, m.Poll{After: "0", Limit: 4})
	if e != nil || len(page.Events) != 2 {
		t.Fatal("event loss", e)
	}
	sealClose(t, restored)
}

func TestMaintenanceUnsealedAndBindingFailClosed(t *testing.T) {
	ctx := context.Background()
	c := guardConfig(t, testConfig(t))
	maintainOK(t, c, "enroll", "")
	copyConfig := c
	copyConfig.RecoveryState += ".copy"
	b, e := os.ReadFile(c.RecoveryState)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(copyConfig.RecoveryState, b, 0600); e != nil {
		t.Fatal(e)
	}
	_, e = Open(ctx, copyConfig)
	requireCode(t, e, "maintenance_configuration_mismatch")
	missing := c
	missing.RecoveryState = ""
	_, e = Open(ctx, missing)
	requireCode(t, e, "service_maintenance_required")
	wrong := c
	wrong.Service = "another"
	_, e = Open(ctx, wrong)
	requireCode(t, e, "maintenance_configuration_mismatch")
	s := openOK(t, c)
	s.Close() // 模拟未执行排空封存的退出。
	_, e = Open(ctx, c)
	requireCode(t, e, "service_reconciliation_required")
	_, e = Maintain(ctx, c, "backup", c.RecoveryState+".backup")
	requireCode(t, e, "service_reconciliation_required")
	if e = os.Remove(c.RecoveryState); e != nil {
		t.Fatal(e)
	}
	_, e = Maintain(ctx, c, "enroll", "")
	requireCode(t, e, "service_maintenance_required")
}

func TestMaintenanceInterruptedImportResumesOnlyExactTarget(t *testing.T) {
	ctx := context.Background()
	c := guardConfig(t, testConfig(t))
	maintainOK(t, c, "enroll", "")
	path := c.RecoveryState + ".backup"
	maintainOK(t, c, "backup", path)
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	crashAfterImport(t, target, path)
	_, e := Open(ctx, c)
	requireCode(t, e, "service_reconciliation_required")
	other := c
	other.DatabaseURL = maintenanceDatabase(t)
	_, e = Maintain(ctx, other, "restore", path)
	requireCode(t, e, "maintenance_target_mismatch")
	maintainOK(t, target, "restore", path)
	restored := openOK(t, target)
	sealClose(t, restored)
}

func TestMaintenanceRejectsCorruptBackupAndChangedStructure(t *testing.T) {
	ctx := context.Background()
	c := guardConfig(t, testConfig(t))
	maintainOK(t, c, "enroll", "")
	path := c.RecoveryState + ".backup"
	maintainOK(t, c, "backup", path)
	var backup serviceBackup
	if e := readPrivate(path, backupLimit, &backup); e != nil {
		t.Fatal(e)
	}
	backup.Snapshot.Tables[0].Rows = nil
	bad := path + ".bad"
	if e := writePrivate(bad, backup, false); e != nil {
		t.Fatal(e)
	}
	target := c
	target.DatabaseURL = maintenanceDatabase(t)
	_, e := Maintain(ctx, target, "restore", bad)
	requireCode(t, e, "service_backup_invalid")
	s, e := connect(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Pool.Exec(ctx, "ALTER TABLE alpha_devices ADD COLUMN unexpected text"); e != nil {
		t.Fatal(e)
	}
	_, e = Open(ctx, c)
	requireCode(t, e, "service_backup_stale")
}

func TestMaintenancePrivateFiles(t *testing.T) {
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "record")
	value := map[string]string{"phase": "sealed"}
	if e = writePrivate(p, value, false); e != nil {
		t.Fatal(e)
	}
	if e = writePrivate(p, value, false); e == nil {
		t.Fatal("overwrote export")
	}
	link := p + ".link"
	if e = os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	var out map[string]string
	if e = readPrivate(link, 1024, &out); e == nil {
		t.Fatal("symlink accepted")
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if e = readPrivate(p, 1024, &out); e == nil {
		t.Fatal("public file accepted")
	}
}
