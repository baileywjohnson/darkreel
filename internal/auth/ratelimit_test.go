package auth

import (
	"net/http"
	"testing"
	"time"
)

func TestAccountLimiterCountsOnlyFailures(t *testing.T) {
	al := NewAccountLimiter(3, time.Minute)
	for i := 0; i < 10; i++ {
		if !al.Allow("u") {
			t.Fatalf("successful attempt %d was limited", i)
		}
		al.Succeeded("u")
	}
	for i := 0; i < 3; i++ {
		if !al.Allow("u") {
			t.Fatalf("failure %d limited early", i)
		}
	}
	if al.Allow("u") {
		t.Fatal("4th failure allowed with max=3")
	}
	if !al.Allow("other") {
		t.Fatal("limit leaked to another username")
	}
}

// The per-account limit trips identically for existing and nonexistent
// usernames, with a distinct 429 rather than the wrong-password message.
func TestLoginLockoutNoEnumeration(t *testing.T) {
	e := newTestEnv(t)
	e.h.AccountLimiter = NewAccountLimiter(3, time.Minute)

	// Correct logins don't consume the budget.
	for i := 0; i < 4; i++ {
		if rec, _ := e.login(testOldPass); rec.Code != http.StatusOK {
			t.Fatalf("login %d: %d", i, rec.Code)
		}
	}

	lockout := func(username string) (int, string) {
		for i := 0; i < 3; i++ {
			rec := e.post("/login", "", map[string]string{"username": username, "password": "wrong-password-123!"})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s failure %d: got %d", username, i, rec.Code)
			}
		}
		rec := e.post("/login", "", map[string]string{"username": username, "password": "wrong-password-123!"})
		return rec.Code, rec.Body.String()
	}
	codeReal, bodyReal := lockout(testUser)
	codeGhost, bodyGhost := lockout("nosuchuser")
	if codeReal != http.StatusTooManyRequests || codeReal != codeGhost || bodyReal != bodyGhost {
		t.Fatalf("lockout differs: existing=%d %q nonexistent=%d %q", codeReal, bodyReal, codeGhost, bodyGhost)
	}
	if bodyReal != AccountLockedMessage+"\n" {
		t.Fatalf("lockout body %q", bodyReal)
	}
	// Once locked, even the right password is refused with the lockout message.
	if rec, _ := e.login(testOldPass); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked account: %d", rec.Code)
	}

	// Recovery has its own bucket: a locked login doesn't block it.
	rec := e.post("/recover", "", map[string]string{"username": testUser,
		"recovery_code": "AAAA", "new_password": testNewPass})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("recover while login locked: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRecoverLockoutNoEnumeration(t *testing.T) {
	e := newTestEnv(t)
	e.h.RecoveryLimiter = NewAccountLimiter(2, time.Minute)

	try := func(username string) *httpResult {
		rec := e.post("/recover", "", map[string]string{"username": username,
			"recovery_code": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "new_password": testNewPass})
		return &httpResult{rec.Code, rec.Body.String()}
	}
	var real, ghost []*httpResult
	for i := 0; i < 3; i++ {
		real = append(real, try(testUser))
		ghost = append(ghost, try("nosuchuser"))
	}
	for i := range real {
		if *real[i] != *ghost[i] {
			t.Fatalf("attempt %d differs: existing=%v nonexistent=%v", i, *real[i], *ghost[i])
		}
	}
	if real[0].code != http.StatusBadRequest || real[2].code != http.StatusTooManyRequests {
		t.Fatalf("unexpected sequence: %v %v %v", *real[0], *real[1], *real[2])
	}
	// The login bucket is untouched.
	if rec, _ := e.login(testOldPass); rec.Code != http.StatusOK {
		t.Fatalf("login after recover lockout: %d", rec.Code)
	}
}

type httpResult struct {
	code int
	body string
}
