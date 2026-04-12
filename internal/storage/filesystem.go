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
		if _, err := rand.Read(padded[4+len(data):]); err != nil {
			return fmt.Errorf("generate chunk padding: %w", err)
		}
	}

	if err := os.WriteFile(path, padded, 0600); err != nil {
		return err
	}
	return os.Chtimes(path, epoch, epoch)
}

// padBufSize is the buffer size used for streaming random padding to disk.
const padBufSize = 64 * 1024

// WriteChunkFromReader streams an encrypted chunk from r directly to disk,
// avoiding buffering the entire chunk in memory. Returns bytes written (data
// only, excluding the 4-byte length prefix and padding).
func (l *Layout) WriteChunkFromReader(userID, mediaID string, index int, r io.Reader, maxBytes int64) (int, error) {
	path := l.ChunkPath(userID, mediaID, index)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Write placeholder length prefix (will be updated after streaming)
	var lenBuf [4]byte
	if _, err := f.Write(lenBuf[:]); err != nil {
		return 0, err
	}

	// Stream data from reader to file, counting bytes
	n, err := io.Copy(f, io.LimitReader(r, maxBytes))
	if err != nil {
		return 0, err
	}
	dataLen := int(n)

	// Update length prefix now that we know the real size
	binary.BigEndian.PutUint32(lenBuf[:], uint32(dataLen))
	if _, err := f.WriteAt(lenBuf[:], 0); err != nil {
		return 0, err
	}

	// Write random padding to reach bucket size
	padSize := paddedSize(dataLen)
	remaining := padSize - dataLen
	buf := make([]byte, padBufSize)
	for remaining > 0 {
		n := remaining
		if n > padBufSize {
			n = padBufSize
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			return 0, fmt.Errorf("generate chunk padding: %w", err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return 0, err
		}
		remaining -= n
	}

	if err := f.Sync(); err != nil {
		return 0, err
	}
	f.Close()
	return dataLen, os.Chtimes(path, epoch, epoch)
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

// ReadChunkStream reads an encrypted chunk, strips padding, and returns a
// streaming reader. Only the 4-byte length prefix is read into memory;
// the chunk data is streamed directly from the file handle.
func (l *Layout) ReadChunkStream(userID, mediaID string, index int) (io.ReadCloser, int64, error) {
	path := l.ChunkPath(userID, mediaID, index)
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(f, lenBuf[:]); err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("read chunk length: %w", err)
	}
	realLen := int64(binary.BigEndian.Uint32(lenBuf[:]))
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(f, realLen), f}, realLen, nil
}

// ReadChunkPaddedFile opens the full padded chunk file for streaming.
// The caller is responsible for closing the returned file.
// Content-Length reveals only the bucket size, not the real chunk size.
func (l *Layout) ReadChunkPaddedFile(userID, mediaID string, index int) (*os.File, int64, error) {
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

// ReadThumbnailPaddedFile opens the full padded thumbnail file for streaming.
// The caller is responsible for closing the returned file.
func (l *Layout) ReadThumbnailPaddedFile(userID, mediaID string) (*os.File, int64, error) {
	path := l.ThumbnailPath(userID, mediaID)
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

// WriteThumbnail writes an encrypted thumbnail to disk, padded to a fixed size.
func (l *Layout) WriteThumbnail(userID, mediaID string, data []byte) error {
	path := l.ThumbnailPath(userID, mediaID)

	// Pad to fixed size to prevent size-based content inference
	padded := make([]byte, 4+paddedThumbSize)
	binary.BigEndian.PutUint32(padded[:4], uint32(len(data)))
	copy(padded[4:], data)
	if pad := paddedThumbSize - len(data); pad > 0 {
		if _, err := rand.Read(padded[4+len(data):]); err != nil {
			return fmt.Errorf("generate thumbnail padding: %w", err)
		}
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
