package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// CleanupOrphans must only ever remove UUID-named user/media directories.
func TestCleanupOrphansIgnoresNonUUIDDirs(t *testing.T) {
	base := t.TempDir()
	l := NewLayout(base)

	keepUser, keepMedia := uuid.New().String(), uuid.New().String()
	orphanUser, orphanMedia := uuid.New().String(), uuid.New().String()
	for _, p := range []string{
		filepath.Join(keepUser, keepMedia),
		filepath.Join(orphanUser, orphanMedia),
		filepath.Join("backups", uuid.New().String()), // operator dir that happens to hold UUID-named subdirs
		filepath.Join(keepUser, "notes"),              // non-UUID dir inside a user dir
	} {
		if err := os.MkdirAll(filepath.Join(base, p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, p, "f"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := l.CleanupOrphans(map[string]bool{keepUser + "/" + keepMedia: true})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed %d directories, want 1", removed)
	}
	for _, p := range []string{"backups", filepath.Join(keepUser, keepMedia), filepath.Join(keepUser, "notes")} {
		if _, err := os.Stat(filepath.Join(base, p, ".")); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(base, orphanUser)); !os.IsNotExist(err) {
		t.Errorf("orphaned user dir not removed: %v", err)
	}
}

func mtime(t *testing.T, p string) int64 {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime().Unix()
}

// Directory mtimes end up at the epoch after an upload's files are written and
// after a media directory is removed.
func TestDirTimesNormalized(t *testing.T) {
	base := t.TempDir()
	l := NewLayout(base)
	user := uuid.New().String()
	a, b := uuid.New().String(), uuid.New().String()

	for _, m := range []string{a, b} {
		if err := l.EnsureMediaDir(user, m); err != nil {
			t.Fatal(err)
		}
		if err := l.WriteThumbnail(user, m, []byte("thumb")); err != nil {
			t.Fatal(err)
		}
		if err := l.WriteChunk(user, m, 0, []byte("chunk")); err != nil {
			t.Fatal(err)
		}
		l.NormalizeDirTimes(user, m)
	}
	userDir := filepath.Join(base, user)
	for _, p := range []string{userDir, l.MediaDir(user, a), l.MediaDir(user, b)} {
		if got := mtime(t, p); got != epoch.Unix() {
			t.Errorf("%s mtime %d after upload, want epoch", p, got)
		}
	}

	if err := l.RemoveMedia(user, a); err != nil {
		t.Fatal(err)
	}
	if got := mtime(t, userDir); got != epoch.Unix() {
		t.Errorf("user dir mtime %d after RemoveMedia, want epoch", got)
	}

	s := NewShredder(l, 1)
	s.QueueMedia(user, b)
	s.Shutdown()
	if _, err := os.Stat(userDir); !os.IsNotExist(err) {
		t.Errorf("empty user dir not removed by shredder: %v", err)
	}
	if got := mtime(t, base); got != epoch.Unix() {
		t.Errorf("data dir mtime %d after shred, want epoch", got)
	}
}
