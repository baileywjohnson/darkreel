package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/baileywjohnson/darkreel/internal/crypto"
)

// Layout manages the directory structure for encrypted media storage.
type Layout struct {
	BaseDir string // e.g., ./data
}

func NewLayout(baseDir string) *Layout {
	return &Layout{BaseDir: baseDir}
}

// MediaDir returns the directory for a specific media item's chunks.
func (l *Layout) MediaDir(userID, mediaID string) string {
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
func (l *Layout) EnsureMediaDir(userID, mediaID string) error {
	return os.MkdirAll(l.MediaDir(userID, mediaID), 0700)
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
