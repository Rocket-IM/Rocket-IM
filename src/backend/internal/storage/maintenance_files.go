package storage

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	m "rocket-im/service/internal/messaging"
	"syscall"
)

const backupLimit = 64 * 1024 * 1024

// 路径的父目录必须预先创建、私有且规范；部署者负责所有祖先目录的可信性。
func privatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return m.Fail("maintenance_path_invalid")
	}
	parent := filepath.Dir(path)
	real, e := filepath.EvalSymlinks(parent)
	if e != nil || real != parent {
		return m.Fail("maintenance_path_invalid")
	}
	info, e := os.Stat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return m.Fail("maintenance_permissions_invalid")
	}
	return nil
}

func readPrivate(path string, limit int64, out any) error {
	if e := privatePath(path); e != nil {
		return e
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return m.Fail("maintenance_file_unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return m.Fail("maintenance_file_invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(f, limit+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return m.Fail("maintenance_file_invalid")
	}
	var tail any
	if decoder.Decode(&tail) != io.EOF {
		return m.Fail("maintenance_file_invalid")
	}
	return nil
}

// 先同步新文件，再原子安装和同步目录；失败不能返回完成。导出使用link拒绝覆盖。
func writePrivate(path string, value any, replace bool) error {
	if e := privatePath(path); e != nil {
		return e
	}
	b, e := json.Marshal(value)
	if e != nil || len(b) > backupLimit {
		return m.Fail("maintenance_size_limit")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".rim-maintenance-*")
	if e != nil {
		return m.Fail("maintenance_write_failed")
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return m.Fail("maintenance_write_failed")
	}
	if e = f.Sync(); e != nil {
		return m.Fail("maintenance_write_failed")
	}
	if e = f.Close(); e != nil {
		return m.Fail("maintenance_write_failed")
	}
	if replace {
		e = os.Rename(name, path)
	} else {
		e = os.Link(name, path)
	}
	if e != nil {
		return m.Fail("maintenance_install_failed")
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return m.Fail("maintenance_sync_failed")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return m.Fail("maintenance_sync_failed")
	}
	return nil
}

func lockMaintenance(path string) (*os.File, error) {
	if e := privatePath(path); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(path+".lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, m.Fail("maintenance_lock_failed")
	}
	f := os.NewFile(uintptr(fd), path+".lock")
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, m.Fail("service_maintenance_busy")
	}
	return f, nil
}
