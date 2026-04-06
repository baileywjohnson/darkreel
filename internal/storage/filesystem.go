package storage

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

// paddedChunkSize is the legacy fixed size for 1 MB chunks on disk.
// 1MB plaintext + 12 nonce + 16 tag = 1048604 bytes max encrypted chunk.
const paddedChunkSize = 1048576 + 28

// paddedSize returns the next bucket size for variable-size chunk padding.
// This prevents size-based fingerprinting while supporting larger fMP4 segments.
func paddedSize(dataLen int) int {
	switch {
	case dataLen <= 1048604:
		return 1048604 // <= 1 MB
	case dataLen <= 2097208:
		return 2097208 // <= 2 MB
	case dataLen <= 4194332:
		return 4194332 // <= 4 MB
	case dataLen <= 8388636:
		return 8388636 // <= 8 MB
	case dataLen <= 16777244:
		return 16777244 // <= 16 MB
	default:
		// Pad to nearest 1 MB boundary
		const mb = 1048576
		return ((dataLen + mb - 1) / mb) * mb
	}
}

// paddedThumbSize is the fixed size for thumbnail files on disk.
// Max thumbnail is ~320px wide JPEG at quality 5, which fits in 256 KB.
const paddedThumbSize = 256 * 1024

// epoch is a fixed timestamp applied to all written files so that
// filesystem modification times don't leak when uploads occurred.
var epoch = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// WriteChunk writes an encrypted chunk to disk, padded to a bucketed size.
// Format: [4 bytes big-endian real length][data][random padding]
func (l *Layout) WriteChunk(userID, mediaID string, index int, data []byte) error {
	path := l.ChunkPath(userID, mediaID, index)

	padSize := paddedSize(len(data))
	padded := make([]byte, 4+padSize)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(data)))
	copy(padded[4:], data)
	// Fill remaining with random bytes so padding isn't distinguishable
	if rem := padSize - len(data); rem > 0 {
		rand.Read(padded[4+len(data):])
	}

	if err := os.WriteFile(path, padded, 0600); err != nil {
		return err
	}
	return os.Chtimes(path, epoch, epoch)
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

// WriteThumbnail writes an encrypted thumbnail to disk, padded to a fixed size.
func (l *Layout) WriteThumbnail(userID, mediaID string, data []byte) error {
	path := l.ThumbnailPath(userID, mediaID)

	// Pad to fixed size to prevent size-based content inference
	padded := make([]byte, 4+paddedThumbSize)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(data)))
	copy(padded[4:], data)
	if pad := paddedThumbSize - len(data); pad > 0 {
		rand.Read(padded[4+len(data):])
	}

	if err := os.WriteFile(path, padded, 0600); err != nil {
		return err
	}
	return os.Chtimes(path, epoch, epoch)
}

// ReadThumbnail reads an encrypted thumbnail from disk, stripping the padding.
func (l *Layout) ReadThumbnail(userID, mediaID string) ([]byte, error) {
	path := l.ThumbnailPath(userID, mediaID)
	padded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read thumbnail: %w", err)
	}
	if len(padded) < 4 {
		return nil, fmt.Errorf("thumbnail too small")
	}
	realLen := binary.BigEndian.Uint32(padded[:4])
	if int(realLen) > len(padded)-4 {
		return nil, fmt.Errorf("invalid thumbnail length")
	}
	return padded[4 : 4+realLen], nil
}
