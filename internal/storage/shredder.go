package storage

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/baileywjohnson/darkreel/internal/crypto"
)

// Shredder processes secure file deletions in the background so HTTP
// handlers can return immediately after the DB record is removed.
// The encrypted data on disk is unrecoverable without the file key
// (already deleted from the DB), so the async window is safe.
type Shredder struct {
	layout *Layout
	queue  chan string // directory paths to shred
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
}

// NewShredder starts a pool of background workers that securely delete
// media directories. Workers defaults to runtime.NumCPU() capped at 8.
func NewShredder(layout *Layout, workers int) *Shredder {
	if workers <= 0 {
		workers = runtime.NumCPU()
		if workers > 8 {
			workers = 8
		}
	}
	s := &Shredder{
		layout: layout,
		queue:  make(chan string, 4096),
	}
	for i := 0; i < workers; i++ {
		go s.worker()
	}
	return s
}

func (s *Shredder) worker() {
	for dir := range s.queue {
		shredDirectory(dir)
		s.wg.Done()
	}
}

// QueueMedia enqueues a media directory for background shredding.
// Returns false if the shredder has been shut down (the caller should
// fall back to synchronous removal via RemoveMedia).
func (s *Shredder) QueueMedia(userID, mediaID string) bool {
	dir := s.layout.MediaDir(userID, mediaID)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.wg.Add(1)
	s.mu.Unlock()
	s.queue <- dir
	return true
}

// Shutdown closes the queue and blocks until all in-flight shred
// operations complete. Call this during graceful server shutdown.
func (s *Shredder) Shutdown() {
	s.mu.Lock()
	s.closed = true
	close(s.queue)
	s.mu.Unlock()
	s.wg.Wait()
}

func shredDirectory(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		os.RemoveAll(dir)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			crypto.ShredFile(filepath.Join(dir, e.Name()))
		}
	}
	os.RemoveAll(dir)
	// Remove parent user directory if now empty (no-op if not empty)
	os.Remove(filepath.Dir(dir))
}
