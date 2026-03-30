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
