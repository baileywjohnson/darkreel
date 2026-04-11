package server

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"sync"
	"time"
)

const maxVisitors = 10000 // cap to prevent memory exhaustion under DDoS

type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	max      int
	window   time.Duration
}

type visitor struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		max:      max,
		window:   window,
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

func (rl *rateLimiter) allow(ip string) bool {
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
			// If still at capacity after eviction, reject to prevent unbounded growth
			if len(rl.visitors) >= maxVisitors {
				return false
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
			// Hash IP to avoid storing plaintext addresses in memory
			// where they could be recovered from a process memory dump.
			h := sha256.Sum256([]byte(ip))
			key := hex.EncodeToString(h[:16])
			if !rl.allow(key) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
