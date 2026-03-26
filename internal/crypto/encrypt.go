package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

const ChunkSize = 1 << 20 // 1 MB

// bufPool reuses chunk-sized buffers to reduce GC pressure.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, ChunkSize)
		return &b
	},
}

// EncryptBlock encrypts a small block (e.g., a file key) with AES-256-GCM.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncryptBlock(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptChunk encrypts a single chunk with AES-256-GCM.
// The chunk index is used as additional authenticated data to prevent reordering.
// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
func EncryptChunk(plaintext, key []byte, chunkIndex int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(chunkIndex))

	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// EncryptReader reads from r in ChunkSize blocks, encrypts each, and writes to w.
// Returns the number of chunks written.
func EncryptReader(r io.Reader, w io.Writer, key []byte) (int, error) {
	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)
	buf := *bufPtr

	chunkIndex := 0
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			enc, encErr := EncryptChunk(buf[:n], key, chunkIndex)
			if encErr != nil {
				return chunkIndex, fmt.Errorf("encrypt chunk %d: %w", chunkIndex, encErr)
			}
			// Write length prefix (4 bytes big-endian) so reader knows chunk boundaries
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(enc)))
			if _, wErr := w.Write(lenBuf); wErr != nil {
				return chunkIndex, wErr
			}
			if _, wErr := w.Write(enc); wErr != nil {
				return chunkIndex, wErr
			}
			chunkIndex++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return chunkIndex, fmt.Errorf("read chunk %d: %w", chunkIndex, err)
		}
	}
	return chunkIndex, nil
}
