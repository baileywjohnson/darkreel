package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const claimsKey contextKey = "claims"

func Middleware(next http.Handler) http.Handler {
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

		if _, ok := Sessions.Get(claims.SessionID); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
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
