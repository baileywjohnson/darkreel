package auth

import (
	"sync"
	"time"
)

const sessionMaxAge = 24 * time.Hour // matches JWT expiry

type sessionEntry struct {
	UserID    string
	MasterKey []byte
	CreatedAt time.Time
}

// SessionStore holds master keys in memory, indexed by session ID.
// Master keys are never persisted to disk.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry // sessionID → entry
}

var Sessions = &SessionStore{
	sessions: make(map[string]*sessionEntry),
}

// StartCleanup launches a background goroutine that removes expired sessions.
func (s *SessionStore) StartCleanup() {
	go func() {
		for {
			time.Sleep(time.Minute)
			s.mu.Lock()
			now := time.Now()
			for sid, entry := range s.sessions {
				if now.Sub(entry.CreatedAt) > sessionMaxAge {
					for i := range entry.MasterKey {
						entry.MasterKey[i] = 0
					}
					delete(s.sessions, sid)
				}
			}
			s.mu.Unlock()
		}
	}()
}

func (s *SessionStore) Set(sessionID, userID string, masterKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	s.sessions[sessionID] = &sessionEntry{UserID: userID, MasterKey: key, CreatedAt: time.Now()}
}

// ClearKey zeroes and removes the master key from a session while keeping
// the session itself alive for authentication. This minimizes the window
// during which the plaintext master key is held in server memory.
func (s *SessionStore) ClearKey(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.sessions[sessionID]; ok {
		for i := range entry.MasterKey {
			entry.MasterKey[i] = 0
		}
		entry.MasterKey = nil
	}
}

func (s *SessionStore) Get(sessionID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	// Expired sessions are rejected immediately
	if time.Since(entry.CreatedAt) > sessionMaxAge {
		return nil, false
	}
	cp := make([]byte, len(entry.MasterKey))
	copy(cp, entry.MasterKey)
	return cp, true
}

// Has checks whether a valid (non-expired) session exists without
// copying the master key into a new allocation.
func (s *SessionStore) Has(sessionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[sessionID]
	if !ok {
		return false
	}
	return time.Since(entry.CreatedAt) <= sessionMaxAge
}

func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.sessions[sessionID]; ok {
		for i := range entry.MasterKey {
			entry.MasterKey[i] = 0
		}
		delete(s.sessions, sessionID)
	}
}

// DeleteAllForUser removes all sessions belonging to a specific user.
func (s *SessionStore) DeleteAllForUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, entry := range s.sessions {
		if entry.UserID == userID {
			for i := range entry.MasterKey {
				entry.MasterKey[i] = 0
			}
			delete(s.sessions, sid)
		}
	}
}
