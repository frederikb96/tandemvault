package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LockPath is the per-machine lock every writer of a sops-dotenv file takes:
// $XDG_RUNTIME_DIR/secret-store-<first 16 hex digits of sha256(absolute path)>.lock.
// Other tools writing the same file take the same flock, so concurrent
// writers never lose each other's change.
func LockPath(storePath string) string {
	abs, err := filepath.Abs(storePath)
	if err != nil {
		abs = storePath
	}
	sum := sha256.Sum256([]byte(abs))
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "secret-store-"+hex.EncodeToString(sum[:])[:16]+".lock")
}

// WithLock runs fn while holding an exclusive flock on path.
func WithLock(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck // released on close anyway
	return fn()
}

// ConflictCopiesOf lists Syncthing conflict copies of path. Syncthing names
// them <stem>.sync-conflict-<date>-<time>-<device><ext>, so a conflict copy of
// ".sops.env" is ".sops.sync-conflict-20260101-120000-ABCDEFG.env".
func ConflictCopiesOf(path string) ([]string, error) {
	dir, base := filepath.Split(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var found []string
	prefix := stem + ".sync-conflict-"
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ext) {
			found = append(found, filepath.Join(dir, n))
		}
	}
	return found, nil
}

// WriteFileAtomic writes content to path through a temporary file and a
// rename, so a reader never sees a half-written file.
func WriteFileAtomic(path string, content []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
