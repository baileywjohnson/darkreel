package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Delegation TTLs.
const (
	// Authorization codes are short-lived and single-use. Two minutes is a
	// comfortable copy/paste window while keeping the window for code theft
	// narrow. Expired codes are deleted on exchange regardless.
	authCodeTTL = 2 * time.Minute

	// Short-lived access tokens minted from a refresh token. One hour matches
	// session JWT policy; revocation of the underlying delegation takes effect
	// when the next refresh is attempted.
	delegationAccessTTL = time.Hour

	// Upper bounds on operator-supplied strings so a malicious consent request
	// can't DoS the DB.
	maxClientNameLen = 128
	maxClientURLLen  = 512

	// v1 ships one scope. Guard against typos / future additions.
	scopeUpload = "upload"
)

// AuthorizeDelegation is called by the Darkreel SPA when the logged-in user
// approves a delegated client. It mints a single-use authorization code tied
// to this user + the declared client identity. The code is displayed to the
// user in the copy-paste consent flow.
//
// Requires a full-scope JWT — a delegated client cannot escalate itself by
// issuing further delegations.
func (h *Handler) AuthorizeDelegation(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	claims := GetClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ClientName string `json:"client_name"`
		ClientURL  string `json:"client_url"`
		Scope      string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	req.ClientName = strings.TrimSpace(req.ClientName)
	req.ClientURL = strings.TrimSpace(req.ClientURL)

	if req.ClientName == "" || len(req.ClientName) > maxClientNameLen {
		http.Error(w, "client_name must be 1..128 characters", http.StatusBadRequest)
		return
	}
	if req.ClientURL == "" || len(req.ClientURL) > maxClientURLLen {
		http.Error(w, "client_url must be 1..512 characters", http.StatusBadRequest)
		return
	}
	// client_url is shown to the user in the "Connected Apps" UI. Restrict to
	// http/https so the UI never renders a javascript: / data: URI.
	if !strings.HasPrefix(req.ClientURL, "https://") && !strings.HasPrefix(req.ClientURL, "http://") {
		http.Error(w, "client_url must be http:// or https://", http.StatusBadRequest)
		return
	}
	if req.Scope != scopeUpload {
		http.Error(w, "scope must be 'upload'", http.StatusBadRequest)
		return
	}

	code, err := randURLToken(24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entry := &db.DelegationCode{
		Code:       code,
		UserID:     claims.UserID,
		ClientName: req.ClientName,
		ClientURL:  req.ClientURL,
		Scope:      req.Scope,
		ExpiresAt:  time.Now().Add(authCodeTTL).Unix(),
	}
	if err := db.InsertDelegationCode(h.DB, entry); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"authorization_code": code,
		"expires_in":         int(authCodeTTL / time.Second),
	})
}

// ExchangeDelegationCode consumes an authorization code and returns the
// credentials the delegated client needs to upload: a refresh token and the
// user's public key. The plaintext refresh token is returned exactly once;
// only sha256(token) is stored server-side.
//
// Unauthenticated — the code is itself the authentication.
func (h *Handler) ExchangeDelegationCode(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		AuthorizationCode string `json:"authorization_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.AuthorizationCode == "" {
		http.Error(w, "authorization_code required", http.StatusBadRequest)
		return
	}

	entry, err := db.ConsumeDelegationCode(h.DB, req.AuthorizationCode, time.Now())
	if err != nil {
		// Both "row not found" and "expired" surface here — reply identically
		// so an attacker probing for a valid code can't distinguish the two.
		http.Error(w, "invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByID(h.DB, entry.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 32 bytes of randomness, URL-safe. Returned once; never retrievable.
	refreshToken, err := randURLToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	delegationID := uuid.New().String()
	d := &db.Delegation{
		ID:         delegationID,
		UserID:     entry.UserID,
		ClientName: entry.ClientName,
		ClientURL:  entry.ClientURL,
		Scope:      entry.Scope,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := db.InsertDelegation(h.DB, d, db.HashRefreshToken(refreshToken)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id":       user.ID,
		"public_key":    base64.StdEncoding.EncodeToString(user.PublicKey),
		"refresh_token": refreshToken,
		"delegation_id": delegationID,
		"scope":         entry.Scope,
	})
}

// RefreshDelegationToken exchanges a refresh token for a short-lived scoped
// JWT. Called by the delegated client immediately before each upload batch.
// Revocation of the backing delegation takes effect here: once deleted, no
// new access tokens can be minted.
//
// Unauthenticated — the refresh token is itself the authentication.
func (h *Handler) RefreshDelegationToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.RefreshToken == "" {
		http.Error(w, "refresh_token required", http.StatusBadRequest)
		return
	}

	d, err := db.GetDelegationByTokenHash(h.DB, db.HashRefreshToken(req.RefreshToken))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if d.Scope != scopeUpload {
		http.Error(w, "unsupported scope", http.StatusForbidden)
		return
	}

	access, err := GenerateDelegationToken(d.UserID, delegationAccessTTL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = db.TouchDelegation(h.DB, d.ID, time.Now()) // best-effort observability

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": access,
		"expires_in":   int(delegationAccessTTL / time.Second),
		"token_type":   "Bearer",
		"scope":        d.Scope,
	})
}

// ListDelegations returns the user's active delegations for display in a
// "Connected Apps" settings panel. Requires a full-scope JWT.
func (h *Handler) ListDelegations(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ds, err := db.ListDelegations(h.DB, claims.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(ds))
	for _, d := range ds {
		entry := map[string]any{
			"id":          d.ID,
			"client_name": d.ClientName,
			"client_url":  d.ClientURL,
			"scope":       d.Scope,
			"created_at":  d.CreatedAt,
		}
		if d.LastUsedAt.Valid {
			entry["last_used_at"] = d.LastUsedAt.String
		}
		out = append(out, entry)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// RevokeDelegation deletes a single delegation. Requires a full-scope JWT
// and verifies ownership — users can only revoke their own delegations.
func (h *Handler) RevokeDelegation(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := db.DeleteDelegation(h.DB, claims.UserID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "delegation not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// StartDelegationCodeCleanup launches a background goroutine that removes
// expired authorization codes. Called from server startup.
func StartDelegationCodeCleanup(database *sql.DB) {
	go func() {
		// Authorization codes are short-lived; a minute-granularity sweep is
		// plenty and keeps the codes table small under consent churn.
		for {
			time.Sleep(time.Minute)
			_ = db.PruneExpiredDelegationCodes(database, time.Now())
		}
	}()
}

// randURLToken returns n bytes of URL-safe base64-encoded randomness.
// The output length is ceil(4n/3) — for n=24 that's 32 chars, for n=32, 43.
func randURLToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
