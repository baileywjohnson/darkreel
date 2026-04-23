package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret []byte
	jwtOnce   sync.Once
)

// ErrSecretAlreadyInitialized is returned by SetSecret when called after
// any token op has already caused the secret to be auto-generated. This is
// surfaced as an error (rather than a silent no-op) so misordered callers
// learn their SetSecret call was discarded and tokens are being signed with
// an ephemeral secret instead of the one they passed in.
var ErrSecretAlreadyInitialized = errors.New("jwt secret already initialized")

const tokenExpiry = 24 * time.Hour

type Claims struct {
	UserID    string `json:"uid"`
	SessionID string `json:"sid"`
	IsAdmin   bool   `json:"adm,omitempty"`
	// Scope is empty for full browser-session tokens and "upload" for tokens
	// minted from a delegation. Handlers use scope to gate which actions a
	// token is allowed to perform — see RequireFullScope.
	Scope string `json:"scp,omitempty"`
	jwt.RegisteredClaims
}

// initSecret generates a random JWT secret if one hasn't been set.
// Uses sync.Once to eliminate the race between SetSecret and auto-generation.
func initSecret() {
	jwtOnce.Do(func() {
		jwtSecret = make([]byte, 64)
		if _, err := rand.Read(jwtSecret); err != nil {
			panic("failed to generate JWT secret: " + err.Error())
		}
	})
}

// SetSecret installs a persistent JWT secret (e.g., from config). Must be
// called before any token op. Returns ErrSecretAlreadyInitialized if called
// after initSecret already auto-generated an ephemeral secret — callers must
// handle this rather than silently getting a different secret than intended.
func SetSecret(secret []byte) error {
	installed := false
	jwtOnce.Do(func() {
		jwtSecret = make([]byte, len(secret))
		copy(jwtSecret, secret)
		installed = true
	})
	if !installed {
		return ErrSecretAlreadyInitialized
	}
	return nil
}

func getSecret() []byte {
	return jwtSecret
}

func GenerateToken(userID, sessionID string, isAdmin bool) (string, error) {
	return generateToken(userID, sessionID, isAdmin, "", tokenExpiry)
}

// GenerateDelegationToken returns a short-lived JWT scoped for delegated uploads.
// The JWT is not tied to a SessionStore entry — delegated clients do not hold
// a server-side session; authorization is derived from the refresh-token
// presentation each time a new access token is minted.
func GenerateDelegationToken(userID string, ttl time.Duration) (string, error) {
	return generateToken(userID, "", false, "upload", ttl)
}

func generateToken(userID, sessionID string, isAdmin bool, scope string, ttl time.Duration) (string, error) {
	initSecret()
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		IsAdmin:   isAdmin,
		Scope:     scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getSecret())
}

func ValidateToken(tokenStr string) (*Claims, error) {
	initSecret()
	secret := getSecret()
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		// Accept only HS256 — the exact algorithm we sign with. Matching the
		// broader SigningMethodHMAC interface would also accept HS384/HS512,
		// which we never issue. Defense-in-depth against future mis-routes.
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func GenerateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate session ID: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}
