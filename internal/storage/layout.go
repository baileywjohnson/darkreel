package storage

import (
	"encoding/binary"
	"fmt"
	"io"
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
// Sets mtimes on both user and media directories to the fixed epoch
// so directory timestamps don't leak when uploads occurred.
func (l *Layout) EnsureMediaDir(userID, mediaID string) error {
	mediaDir := l.MediaDir(userID, mediaID)
	if err := os.MkdirAll(mediaDir, 0700); err != nil {
		return err
	}
	// Coarsen directory timestamps to match file epoch
	userDir := filepath.Join(l.BaseDir, userID)
	os.Chtimes(userDir, epoch, epoch)
	os.Chtimes(mediaDir, epoch, epoch)
	return nil
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
			if err != nil || !mInfo.IsDir() || mInfo.Mode()&os.ModeSymlink != 0 {
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
	}
	return removed, nil
}

// IsMediaComplete checks that all expected chunk files and the thumbnail exist on disk.
func (l *Layout) IsMediaComplete(userID, mediaID string, chunkCount int) bool {
	// Check thumbnail
	if _, err := os.Stat(l.ThumbnailPath(userID, mediaID)); err != nil {
		return false
	}
	// Check all chunks
	for i := 0; i < chunkCount; i++ {
		if _, err := os.Stat(l.ChunkPath(userID, mediaID, i)); err != nil {
			return false
		}
	}
	return true
}

// MediaChunkBytes returns the total raw (pre-padding) byte size of all chunks for a media item.
// Used to backfill size_bytes for records where the server crashed before updating the DB.
// Only reads the 4-byte length prefix from each chunk file instead of loading entire chunks.
func (l *Layout) MediaChunkBytes(userID, mediaID string, chunkCount int) int64 {
	var total int64
	for i := 0; i < chunkCount; i++ {
		path := l.ChunkPath(userID, mediaID, i)
		f, err := os.Open(path)
		if err != nil {
			return 0 // incomplete — caller should handle
		}
		var lenBuf [4]byte
		_, err = io.ReadFull(f, lenBuf[:])
		f.Close()
		if err != nil {
			return 0
		}
		total += int64(binary.BigEndian.Uint32(lenBuf[:]))
	}
	return total
}

// RemoveMedia securely shreds all files for a media item, then removes the directory.
func (l *Layout) RemoveMedia(userID, mediaID string) error {
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
