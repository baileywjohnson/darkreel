package auth

import (
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
	visitors map[string]*accountVisitor
	max      int
	window   time.Duration
}

type accountVisitor struct {
	count   int
	resetAt time.Time
}

func NewAccountLimiter(max int, window time.Duration) *AccountLimiter {
	al := &AccountLimiter{
		visitors: make(map[string]*accountVisitor),
		max:      max,
		window:   window,
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

// Allow returns true if the username has not exceeded its rate limit.
func (al *AccountLimiter) Allow(username string) bool {
	al.mu.Lock()
	defer al.mu.Unlock()

	now := time.Now()
	v, ok := al.visitors[username]
	if !ok || now.After(v.resetAt) {
		if len(al.visitors) >= accountMaxVisitors {
			for k, entry := range al.visitors {
				if now.After(entry.resetAt) {
					delete(al.visitors, k)
				}
			}
		}
		al.visitors[username] = &accountVisitor{count: 1, resetAt: now.Add(al.window)}
		return true
	}
	v.count++
	return v.count <= al.max
}
