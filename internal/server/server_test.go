package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func clientAddrSeen(t *testing.T, mw func(http.Handler) http.Handler, remote string, headers map[string]string) string {
	t.Helper()
	var seen string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.RemoteAddr }))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return seen
}

func TestTrustProxy(t *testing.T) {
	local := mustCIDRs(t, "127.0.0.1/32", "::1/128")
	cases := []struct {
		name    string
		cidrs   []*net.IPNet
		remote  string
		headers map[string]string
		want    string
	}{
		{"proxy appends client", local, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "203.0.113.7"}, "203.0.113.7"},
		{"client-supplied XFF prefix ignored", local, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.7"}, "203.0.113.7"},
		{"X-Real-IP and True-Client-IP ignored", local, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "9.9.9.9", "True-Client-IP": "8.8.8.8"}, "203.0.113.7"},
		{"untrusted peer keeps its address", local, "198.51.100.1:5555",
			map[string]string{"X-Forwarded-For": "203.0.113.7"}, "198.51.100.1:5555"},
		{"malformed hop keeps peer", local, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "not-an-ip"}, "127.0.0.1:5555"},
		{"trusted proxy hops skipped", mustCIDRs(t, "127.0.0.1/32", "10.0.0.0/8"), "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "6.6.6.6, 203.0.113.7, 10.1.2.3"}, "203.0.113.7"},
		{"legacy mode takes rightmost", nil, "127.0.0.1:5555",
			map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.7"}, "203.0.113.7"},
		{"no XFF keeps peer", local, "127.0.0.1:5555", nil, "127.0.0.1:5555"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientAddrSeen(t, trustProxy(tc.cidrs), tc.remote, tc.headers); got != tc.want {
				t.Errorf("RemoteAddr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimitGroupsIPv6By64(t *testing.T) {
	mw := RateLimit(1, time.Minute)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	status := func(remote string) int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if s := status("[2001:db8:1:2::1]:1"); s != http.StatusOK {
		t.Fatalf("first request: %d", s)
	}
	if s := status("[2001:db8:1:2::ffff]:1"); s != http.StatusTooManyRequests {
		t.Errorf("same /64 got %d, want 429", s)
	}
	if s := status("[2001:db8:1:3::1]:1"); s != http.StatusOK {
		t.Errorf("different /64 got %d, want 200", s)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	release := make(chan struct{})
	var inFlight sync.WaitGroup
	mw := ConcurrencyLimit(2, 50*time.Millisecond)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight.Done()
		<-release
	}))
	inFlight.Add(2)
	done := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
			done <- struct{}{}
		}()
	}
	inFlight.Wait() // both slots held

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("third concurrent request: %d (Retry-After %q), want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	close(release)
	<-done
	<-done
}
