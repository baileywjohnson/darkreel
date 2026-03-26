package storage

import (
	"fmt"
	"io"
	"os"
)

// WriteChunk writes an encrypted chunk to disk.
func (l *Layout) WriteChunk(userID, mediaID string, index int, data []byte) error {
	path := l.ChunkPath(userID, mediaID, index)
	return os.WriteFile(path, data, 0600)
}

// ReadChunk reads an encrypted chunk from disk.
func (l *Layout) ReadChunk(userID, mediaID string, index int) ([]byte, error) {
	path := l.ChunkPath(userID, mediaID, index)
	return os.ReadFile(path)
}

// ReadChunkStream opens an encrypted chunk for streaming.
func (l *Layout) ReadChunkStream(userID, mediaID string, index int) (io.ReadCloser, int64, error) {
	path := l.ChunkPath(userID, mediaID, index)
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// WriteThumbnail writes an encrypted thumbnail to disk.
func (l *Layout) WriteThumbnail(userID, mediaID string, data []byte) error {
	path := l.ThumbnailPath(userID, mediaID)
	return os.WriteFile(path, data, 0600)
}

// ReadThumbnail reads an encrypted thumbnail from disk.
func (l *Layout) ReadThumbnail(userID, mediaID string) ([]byte, error) {
	path := l.ThumbnailPath(userID, mediaID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read thumbnail: %w", err)
	}
	return data, nil
}
