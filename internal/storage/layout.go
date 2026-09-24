package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/google/uuid"
)

// Layout manages the directory structure for encrypted media storage.
type Layout struct {
	BaseDir string // e.g., ./data
}

func NewLayout(baseDir string) *Layout {
	return &Layout{BaseDir: baseDir}
}

// MediaDir returns the directory for a specific media item's chunks.
// Defense-in-depth: validates IDs as UUIDs to prevent path traversal.
// Upstream handlers already validate, but we verify at the storage layer too.
func (l *Layout) MediaDir(userID, mediaID string) string {
	if _, err := uuid.Parse(userID); err != nil {
		return filepath.Join(l.BaseDir, "_invalid", "_invalid")
	}
	if _, err := uuid.Parse(mediaID); err != nil {
		return filepath.Join(l.BaseDir, "_invalid", "_invalid")
	}
	return filepath.Join(l.BaseDir, userID, mediaID)
}

// ChunkPath returns the path to a specific encrypted chunk.
func (l *Layout) ChunkPath(userID, mediaID string, index int) string {
	return filepath.Join(l.MediaDir(userID, mediaID), fmt.Sprintf("%06d.enc", index))
}

// ThumbnailPath returns the path to the encrypted thumbnail.
func (l *Layout) ThumbnailPath(userID, mediaID string) string {
	return filepath.Join(l.MediaDir(userID, mediaID), "thumb.enc")
}

// EnsureMediaDir creates the media directory if it doesn't exist.
// Creating it bumps the user directory's mtime, so that is reset to the fixed
// epoch here. The media directory's own mtime changes with every file written
// into it; the upload handler resets it with NormalizeDirTimes once all files
// are in place.
func (l *Layout) EnsureMediaDir(userID, mediaID string) error {
	mediaDir := l.MediaDir(userID, mediaID)
	if err := os.MkdirAll(mediaDir, 0700); err != nil {
		return err
	}
	l.normalizeUserDirTimes(userID)
	return nil
}

// NormalizeDirTimes resets the atime/mtime of a media directory and its user
// directory to the fixed epoch. Call it after the last file has been written
// into the media directory — any later create/remove bumps the mtime again.
//
// Only atime and mtime can be set from userspace. The inode change time
// (ctime) and, on filesystems that record it, the birth time still show when
// each file and directory was created or last changed; see README.
func (l *Layout) NormalizeDirTimes(userID, mediaID string) {
	os.Chtimes(l.MediaDir(userID, mediaID), epoch, epoch)
	l.normalizeUserDirTimes(userID)
}

// normalizeUserDirTimes resets the user directory's timestamps after a media
// directory was created in or removed from it, and the data directory's,
// which changes when a user directory comes or goes. Best-effort: the user
// directory may itself have just been removed.
func (l *Layout) normalizeUserDirTimes(userID string) {
	if !isUUIDName(userID) {
		return
	}
	os.Chtimes(filepath.Join(l.BaseDir, userID), epoch, epoch)
	os.Chtimes(l.BaseDir, epoch, epoch)
}

// isUUIDName reports whether name is a hyphenated UUID — the only form of
// user and media directory names Darkreel creates.
func isUUIDName(name string) bool {
	if len(name) != 36 {
		return false
	}
	_, err := uuid.Parse(name)
	return err == nil
}

// SyncMediaDir fsyncs the media directory to ensure all written chunks are
// durable on disk. Called once after all chunks are written, instead of
// per-chunk fsync, to reduce I/O overhead while maintaining durability.
func (l *Layout) SyncMediaDir(userID, mediaID string) error {
	dir := l.MediaDir(userID, mediaID)
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	return err
}

// CleanupOrphans removes data directories that are not referenced in the DB.
// validPaths is a set of "userID/mediaID" strings that should be kept.
//
// Only UUID-named user directories and UUID-named media directories inside
// them are considered. Anything else in the data directory (an operator's
// backups folder, a restore staging area) is never touched.
func (l *Layout) CleanupOrphans(validPaths map[string]bool) (int, error) {
	removed := 0
	topEntries, err := os.ReadDir(l.BaseDir)
	if err != nil {
		return 0, err
	}

	for _, userEntry := range topEntries {
		// Use Lstat to detect symlinks — never follow them
		userDir := filepath.Join(l.BaseDir, userEntry.Name())
		info, err := os.Lstat(userDir)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		userID := userEntry.Name()
		if !isUUIDName(userID) {
			continue
		}

		// Check if this user directory has any valid media
		mediaEntries, err := os.ReadDir(userDir)
		if err != nil {
			continue
		}

		hasValid := false
		for _, mediaEntry := range mediaEntries {
			// Skip symlinks inside user directories too
			mediaDir := filepath.Join(userDir, mediaEntry.Name())
			mInfo, err := os.Lstat(mediaDir)
			if err != nil || !mInfo.IsDir() || mInfo.Mode()&os.ModeSymlink != 0 || !isUUIDName(mediaEntry.Name()) {
				continue
			}
			key := userID + "/" + mediaEntry.Name()
			if validPaths[key] {
				hasValid = true
			} else {
				// Orphaned media directory — shred and remove
				files, _ := os.ReadDir(mediaDir)
				for _, f := range files {
					if !f.IsDir() {
						crypto.ShredFile(filepath.Join(mediaDir, f.Name()))
					}
				}
				os.RemoveAll(mediaDir)
				removed++
			}
		}

		// If no valid media left, remove the empty user directory
		if !hasValid {
			os.Remove(userDir) // only removes if empty
		}
		l.normalizeUserDirTimes(userID)
	}
	return removed, nil
}

// IsMediaComplete checks that all expected chunk files and the thumbnail exist on disk.
//
// Only a file that definitely does not exist counts as missing. Any other
// stat error (EACCES after a restore that didn't chown, EIO) reports the
// item as complete: the caller deletes incomplete items' DB rows — the only
// copy of their sealed keys — so a transient or permission error must never
// be mistaken for an incomplete upload.
func (l *Layout) IsMediaComplete(userID, mediaID string, chunkCount int) bool {
	missing := func(path string) bool {
		_, err := os.Stat(path)
		return errors.Is(err, fs.ErrNotExist)
	}
	if missing(l.ThumbnailPath(userID, mediaID)) {
		return false
	}
	for i := 0; i < chunkCount; i++ {
		if missing(l.ChunkPath(userID, mediaID, i)) {
			return false
		}
	}
	return true
}

// MediaDiskBytes returns the on-disk size of a media item's chunk files plus
// its thumbnail — the figure quota is charged on. Returns 0 if any file is
// missing (incomplete upload; caller should handle).
func (l *Layout) MediaDiskBytes(userID, mediaID string, chunkCount int) int64 {
	var total int64
	for i := 0; i < chunkCount; i++ {
		info, err := os.Lstat(l.ChunkPath(userID, mediaID, i))
		if err != nil || !info.Mode().IsRegular() {
			return 0
		}
		total += info.Size()
	}
	info, err := os.Lstat(l.ThumbnailPath(userID, mediaID))
	if err != nil || !info.Mode().IsRegular() {
		return 0
	}
	return total + info.Size()
}

// RemoveMedia securely shreds all files for a media item, then removes the
// directory and resets the user directory's timestamps, which the removal
// bumped.
func (l *Layout) RemoveMedia(userID, mediaID string) error {
	defer l.normalizeUserDirTimes(userID)
	dir := l.MediaDir(userID, mediaID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return os.RemoveAll(dir) // fallback if dir can't be read
	}
	for _, e := range entries {
		if !e.IsDir() {
			crypto.ShredFile(filepath.Join(dir, e.Name()))
		}
	}
	return os.RemoveAll(dir)
}
