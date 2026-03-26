package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
)

const shredPasses = 3

// ShredFile securely deletes a file by overwriting it multiple times before unlinking.
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
	for pass := 0; pass < shredPasses; pass++ {
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			return fmt.Errorf("seek for shred pass %d: %w", pass, err)
		}
		remaining := size
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			if _, err := rand.Read(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("rand read for shred: %w", err)
			}
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("write for shred pass %d: %w", pass, err)
			}
			remaining -= n
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("sync for shred pass %d: %w", pass, err)
		}
	}

	f.Close()
	return os.Remove(path)
}
