package storage

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// paddedChunkSize is the fixed size for all chunk files on disk.
// 1MB plaintext + 12 nonce + 16 tag = 1048604 bytes max encrypted chunk.
// We pad all chunks to this size to prevent size-based fingerprinting.
const paddedChunkSize = 1048576 + 28

// WriteChunk writes an encrypted chunk to disk, padded to a fixed size.
// Format: [4 bytes big-endian real length][data][random padding]
func (l *Layout) WriteChunk(userID, mediaID string, index int, data []byte) error {
	path := l.ChunkPath(userID, mediaID, index)

	padded := make([]byte, 4+paddedChunkSize)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(data)))
	copy(padded[4:], data)
	// Fill remaining with random bytes so padding isn't distinguishable
	if pad := 4 + paddedChunkSize - 4 - len(data); pad > 0 {
		rand.Read(padded[4+len(data):])
	}

	return os.WriteFile(path, padded, 0600)
}

// ReadChunk reads an encrypted chunk from disk, stripping the padding.
func (l *Layout) ReadChunk(userID, mediaID string, index int) ([]byte, error) {
	path := l.ChunkPath(userID, mediaID, index)
	padded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(padded) < 4 {
		return nil, fmt.Errorf("chunk too small")
	}
	realLen := binary.BigEndian.Uint32(padded[:4])
	if int(realLen) > len(padded)-4 {
		return nil, fmt.Errorf("invalid chunk length")
	}
	return padded[4 : 4+realLen], nil
}

// ReadChunkStream reads an encrypted chunk, strips padding, and returns a reader.
func (l *Layout) ReadChunkStream(userID, mediaID string, index int) (io.ReadCloser, int64, error) {
	data, err := l.ReadChunk(userID, mediaID, index)
	if err != nil {
		return nil, 0, err
	}
	return io.NopCloser(io.NewSectionReader(readerAt(data), 0, int64(len(data)))), int64(len(data)), nil
}

type readerAt []byte

func (r readerAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(r)) {
		return 0, io.EOF
	}
	n = copy(p, r[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
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
