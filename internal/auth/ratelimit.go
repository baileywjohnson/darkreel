package auth

import (
	"hash/maphash"
	"sync"
	"time"
)

const accountMaxVisitors = 10000

// AccountLimiter rate-limits by account name (username) to prevent distributed
// brute-force attacks against a single account. All attempted usernames are
// tracked — including non-existent ones — to avoid leaking whether an account
// exists via rate-limit timing differences.
type AccountLimiter struct {
	mu       sync.Mutex
	visitors map[uint64]*accountVisitor
	max      int
	window   time.Duration
	// hashSeed is a per-process random seed used with hash/maphash (SipHash).
	// Unlike FNV-1a, this prevents an attacker from crafting username
	// collisions to consume another user's rate-limit budget.
	hashSeed maphash.Seed
}

type accountVisitor struct {
	count   int
	resetAt time.Time
}

func NewAccountLimiter(max int, window time.Duration) *AccountLimiter {
	al := &AccountLimiter{
		visitors: make(map[uint64]*accountVisitor),
		max:      max,
		window:   window,
		hashSeed: maphash.MakeSeed(),
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			al.cleanup()
		}
	}()
	return al
}

func (al *AccountLimiter) cleanup() {
	al.mu.Lock()
	defer al.mu.Unlock()
	now := time.Now()
	for k, v := range al.visitors {
		if now.After(v.resetAt) {
			delete(al.visitors, k)
		}
	}
}

// hashUsername returns a keyed hash of the username. The seed is random
// per-process, so an attacker cannot precompute collisions to consume
// another user's rate-limit budget. Also avoids storing plaintext usernames
// in memory where they could be recovered from a process memory dump.
func (al *AccountLimiter) hashUsername(username string) uint64 {
	var h maphash.Hash
	h.SetSeed(al.hashSeed)
	h.WriteString(username)
	return h.Sum64()
}

// Allow returns true if the username has not exceeded its rate limit.
func (al *AccountLimiter) Allow(username string) bool {
	al.mu.Lock()
	defer al.mu.Unlock()

	key := al.hashUsername(username)
	now := time.Now()
	v, ok := al.visitors[key]
	if !ok || now.After(v.resetAt) {
		if len(al.visitors) >= accountMaxVisitors {
			// First pass: evict expired entries
			for k, entry := range al.visitors {
				if now.After(entry.resetAt) {
					delete(al.visitors, k)
				}
			}
			// Second pass: if still at capacity, evict the oldest entry (LRU)
			// to prevent a botnet from filling the map and blocking all logins
			if len(al.visitors) >= accountMaxVisitors {
				var oldestKey uint64
				var oldestTime time.Time
				first := true
				for k, entry := range al.visitors {
					if first || entry.resetAt.Before(oldestTime) {
						oldestKey = k
						oldestTime = entry.resetAt
						first = false
					}
				}
				if !first {
					delete(al.visitors, oldestKey)
				}
			}
		}
		al.visitors[key] = &accountVisitor{count: 1, resetAt: now.Add(al.window)}
		return true
	}
	v.count++
	return v.count <= al.max
}
