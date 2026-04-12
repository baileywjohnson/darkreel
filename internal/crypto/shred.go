package crypto

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
)

// newShredRNG creates a fast PRNG seeded from crypto/rand for overwriting files
// during secure deletion. Each caller gets its own instance to avoid concurrent
// access to a shared PRNG (math/rand.Rand is not goroutine-safe). The overwrite
// data does not need cryptographic quality — the files are already AES-256-GCM
// encrypted and the keys are deleted before shredding.
func newShredRNG() *rand.Rand {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		panic("failed to seed shred PRNG: " + err.Error())
	}
	return rand.New(rand.NewChaCha8(seed))
}

// ShredFile securely deletes a file by overwriting it once with pseudo-random
// data before unlinking. A single pass is sufficient because the file content
// is already AES-256-GCM encrypted and the encryption keys are deleted from
// the database before shredding begins — the ciphertext is computationally
// unrecoverable regardless of physical media recovery.
func ShredFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open for shred: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("stat for shred: %w", err)
	}
	size := info.Size()

	rng := newShredRNG() // per-call PRNG avoids concurrent access to a shared instance
	buf := make([]byte, 64*1024) // 64KB write buffer
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return fmt.Errorf("seek for shred: %w", err)
	}
	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		fillRandBuf(rng, buf[:n])
		if _, err := f.Write(buf[:n]); err != nil {
			f.Close()
			return fmt.Errorf("write for shred: %w", err)
		}
		remaining -= n
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync for shred: %w", err)
	}

	f.Close()
	return os.Remove(path)
}

// fillRandBuf fills buf with fast pseudo-random bytes from the given PRNG.
func fillRandBuf(rng *rand.Rand, buf []byte) {
	for i := 0; i < len(buf); i += 8 {
		v := rng.Uint64()
		remaining := len(buf) - i
		if remaining >= 8 {
			binary.LittleEndian.PutUint64(buf[i:], v)
		} else {
			for j := 0; j < remaining; j++ {
				buf[i+j] = byte(v >> (j * 8))
			}
		}
	}
}

// NewPadRNG creates a new fast PRNG suitable for padding or overwrite data.
// Each goroutine that calls FillRandBuf should use its own instance.
func NewPadRNG() *rand.Rand {
	return newShredRNG()
}

// FillRandBuf fills buf with fast pseudo-random bytes from rng.
func FillRandBuf(rng *rand.Rand, buf []byte) {
	fillRandBuf(rng, buf)
}
