package auth

import (
	"sync"
)

type sessionEntry struct {
	UserID    string
	MasterKey []byte
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

func (s *SessionStore) Set(sessionID, userID string, masterKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	s.sessions[sessionID] = &sessionEntry{UserID: userID, MasterKey: key}
}

func (s *SessionStore) Get(sessionID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	cp := make([]byte, len(entry.MasterKey))
	copy(cp, entry.MasterKey)
	return cp, true
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
