package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An account an admin creates can only change its password (or log out)
// until it has; the change clears the restriction.
func TestAdminCreatedAccountMustChangePassword(t *testing.T) {
	e := newTestEnv(t)
	// The restriction allows the real change-password route by path.
	e.mux.Handle("POST /api/auth/change-password", Middleware(e.db)(http.HandlerFunc(e.h.ChangePassword)))
	const user, pass, newPass = "bobuser", "Admin-Chosen-Pass1!", "Bobs-Own-Passw0rd!"

	// Create the account through the admin handler.
	b, _ := json.Marshal(createUserRequest{Username: user, Password: pass})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users", bytes.NewReader(b))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, &Claims{UserID: e.userID, IsAdmin: true}))
	rec := httptest.NewRecorder()
	e.h.CreateUser(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create: %d %s", rec.Code, rec.Body)
	}

	login := func(p string) map[string]any {
		t.Helper()
		rec := e.post("/login", "", map[string]string{"username": user, "password": p})
		if rec.Code != http.StatusOK {
			t.Fatalf("login: %d %s", rec.Code, rec.Body)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	first := login(pass)
	if first["must_change_password"] != true {
		t.Fatalf("login response missing must_change_password: %v", first)
	}
	tok := first["token"].(string)
	if rec := e.post("/upload", tok, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("restricted session could reach another endpoint: %d", rec.Code)
	}

	rec = e.post("/api/auth/change-password", tok, map[string]string{"old_password": pass, "new_password": newPass})
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password while restricted: %d %s", rec.Code, rec.Body)
	}
	var changed map[string]any
	json.Unmarshal(rec.Body.Bytes(), &changed)
	if rec := e.post("/upload", changed["token"].(string), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("session after the change still restricted: %d", rec.Code)
	}
	if again := login(newPass); again["must_change_password"] == true {
		t.Fatal("flag not cleared by the password change")
	}

	// Self-registered and bootstrap accounts are never restricted.
	if own := e.post("/login", "", map[string]string{"username": testUser, "password": testOldPass}); bytes.Contains(own.Body.Bytes(), []byte("must_change_password")) {
		t.Fatal("bootstrap admin flagged")
	}
}
