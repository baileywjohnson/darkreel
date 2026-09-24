package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Delegation access tokens stop working as soon as the delegation is revoked,
// not when they expire.
func TestDelegationTokenRevokedImmediately(t *testing.T) {
	e := newTestEnv(t)
	id := uuid.New().String()
	if _, err := e.db.Exec(`INSERT INTO delegations (id, user_id, client_name, client_url, scope, refresh_token_hash, created_at)
		VALUES (?, ?, 'app', 'https://app', 'upload', ?, '2026-01-01')`, id, e.userID, db.HashRefreshToken("rt")); err != nil {
		t.Fatal(err)
	}

	tok, err := GenerateDelegationToken(e.userID, id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.post("/upload", tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("live delegation token rejected: %d", rec.Code)
	}

	// A token naming the delegation but another user is refused.
	other, _ := GenerateDelegationToken(uuid.New().String(), id, time.Hour)
	if rec := e.post("/upload", other, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token for another user accepted: %d", rec.Code)
	}
	// Tokens minted before the delegation ID claim existed are refused.
	legacy, _ := generateToken(e.userID, "", false, "upload", "", time.Hour)
	if rec := e.post("/upload", legacy, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token without delegation ID accepted: %d", rec.Code)
	}

	// Revoke through the handler, as the Connected Apps panel does.
	req := httptest.NewRequest(http.MethodDelete, "/api/account/delegations/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, claimsKey, &Claims{UserID: e.userID})
	rec := httptest.NewRecorder()
	e.h.RevokeDelegation(rec, req.WithContext(ctx))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}

	if rec := e.post("/upload", tok, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked delegation token still accepted: %d", rec.Code)
	}
}

// Deleting the account removes its delegations (ON DELETE CASCADE), which
// cuts off their access tokens.
func TestDelegationTokenDiesWithAccount(t *testing.T) {
	e := newTestEnv(t)
	id := uuid.New().String()
	if _, err := e.db.Exec(`INSERT INTO delegations (id, user_id, client_name, client_url, scope, refresh_token_hash, created_at)
		VALUES (?, ?, 'app', 'https://app', 'upload', ?, '2026-01-01')`, id, e.userID, db.HashRefreshToken("rt")); err != nil {
		t.Fatal(err)
	}
	tok, _ := GenerateDelegationToken(e.userID, id, time.Hour)
	if rec := e.post("/upload", tok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("live delegation token rejected: %d", rec.Code)
	}
	// A second admin, so the first may be deleted.
	if _, err := BootstrapAdmin(e.db, "bob", testNewPass); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUserAtomic(e.db, e.userID); err != nil {
		t.Fatal(err)
	}
	if rec := e.post("/upload", tok, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("delegation token of a deleted account still accepted: %d", rec.Code)
	}
}
