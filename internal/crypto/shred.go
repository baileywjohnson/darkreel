package crypto

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"os"
)

// shredRNG is a fast PRNG seeded from crypto/rand, used for overwriting files
// during secure deletion. The overwrite data does not need cryptographic quality —
// the files are already AES-256-GCM encrypted and the keys are deleted before
// shredding, so any random-looking data suffices.
var shredRNG = newShredRNG()

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
		fillShredBuf(buf[:n])
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

// fillShredBuf fills buf with fast pseudo-random bytes from the shred PRNG.
func fillShredBuf(buf []byte) {
	for i := 0; i < len(buf); i += 8 {
		v := shredRNG.Uint64()
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
