package server

import (
	"hash/maphash"
	"net"
	"net/http"
	"sync"
	"time"
)

const maxVisitors = 10000 // cap to prevent memory exhaustion under DDoS

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[uint64]*visitor
	max      int
	window   time.Duration
	// hashSeed is a per-process random seed used with hash/maphash (SipHash).
	// Prevents an attacker from crafting IP collisions to consume another
	// client's rate-limit budget.
	hashSeed maphash.Seed
}

type visitor struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[uint64]*visitor),
		max:      max,
		window:   window,
		hashSeed: maphash.MakeSeed(),
	}
	// Cleanup stale entries every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, v := range rl.visitors {
		if now.After(v.resetAt) {
			delete(rl.visitors, ip)
		}
	}
}

func (rl *rateLimiter) allow(ip uint64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[ip]
	if !ok || now.After(v.resetAt) {
		// Evict expired entries if map is at capacity
		if len(rl.visitors) >= maxVisitors {
			for k, entry := range rl.visitors {
				if now.After(entry.resetAt) {
					delete(rl.visitors, k)
				}
			}
			// If still at capacity after eviction, evict the oldest entry (LRU)
			if len(rl.visitors) >= maxVisitors {
				var oldestKey uint64
				var oldestTime time.Time
				first := true
				for k, entry := range rl.visitors {
					if first || entry.resetAt.Before(oldestTime) {
						oldestKey = k
						oldestTime = entry.resetAt
						first = false
					}
				}
				if !first {
					delete(rl.visitors, oldestKey)
				}
			}
		}
		rl.visitors[ip] = &visitor{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	v.count++
	return v.count <= rl.max
}

// RateLimit returns middleware that limits requests per IP.
// Uses r.RemoteAddr which is set by chi's RealIP middleware when behind a proxy,
// falling back to the direct connection address. The port suffix is stripped
// so each IP gets a single bucket regardless of ephemeral port.
func RateLimit(max int, window time.Duration) func(http.Handler) http.Handler {
	rl := newRateLimiter(max, window)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			// Strip port from "host:port" — RemoteAddr always includes port
			// when set by net/http, and RealIP may also leave it on.
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			// Keyed hash (SipHash via hash/maphash) with a per-process random
			// seed. Avoids storing plaintext IPs in memory AND prevents an
			// attacker from crafting IP collisions to consume another
			// client's budget.
			var h maphash.Hash
			h.SetSeed(rl.hashSeed)
			h.WriteString(ip)
			key := h.Sum64()
			if !rl.allow(key) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
