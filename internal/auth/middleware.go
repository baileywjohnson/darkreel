package auth

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/baileywjohnson/darkreel/internal/db"
)

type contextKey string

const claimsKey contextKey = "claims"

// Middleware authenticates the bearer token and rejects tokens whose backing
// credential has been revoked (see CredentialLive).
func Middleware(database *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := ""

			// Only accept tokens from the Authorization header (not cookies)
			// to prevent CSRF attacks on state-changing endpoints.
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				tokenStr = strings.TrimPrefix(auth, "Bearer ")
			}

			if tokenStr == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			claims, err := ValidateToken(tokenStr)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			live, err := CredentialLive(database, claims)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !live {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CredentialLive reports whether the credential behind a validly signed token
// still exists. Full browser-session tokens (scope="") must correspond to a
// live SessionStore entry — that's how logout/password-change/session cleanup
// revokes them. Delegation tokens must name a delegation row that still
// exists for the same user — revoking the delegation, changing the password,
// recovering the account or deleting it all remove that row, and the token
// stops working on its next request. One primary-key lookup per request.
func CredentialLive(database *sql.DB, claims *Claims) (bool, error) {
	if claims.Scope == "" {
		return Sessions.Has(claims.SessionID), nil
	}
	// Delegation tokens issued before the delegation ID claim existed carry
	// none; they are refused and the client simply refreshes.
	if claims.DelegationID == "" {
		return false, nil
	}
	return db.DelegationExists(database, claims.DelegationID, claims.UserID)
}

// RequireFullScope rejects tokens minted from a delegation. Apply it on every
// route that is NOT the upload endpoint, so a stolen delegation token cannot
// list, read, delete, or otherwise exercise account authority beyond its
// intended upload-only grant.
func RequireFullScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c := GetClaims(r); c != nil && c.Scope != "" {
			http.Error(w, "delegation tokens are scope-limited and cannot access this endpoint", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireUploadScope passes both full tokens and explicit "upload"-scoped
// tokens, and rejects any other scope. Browser uploads therefore keep
// working with the normal session JWT.
func RequireUploadScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := GetClaims(r)
		if c == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if c.Scope != "" && c.Scope != "upload" {
			http.Error(w, "scope not permitted for this endpoint", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(claimsKey).(*Claims)
	return claims
}

func GetUserID(r *http.Request) string {
	if c := GetClaims(r); c != nil {
		return c.UserID
	}
	return ""
}

func GetMasterKey(r *http.Request) ([]byte, bool) {
	claims := GetClaims(r)
	if claims == nil {
		return nil, false
	}
	return Sessions.Get(claims.SessionID)
}
