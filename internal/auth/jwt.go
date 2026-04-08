package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret   []byte
	jwtSecretMu sync.RWMutex
)

const tokenExpiry = 24 * time.Hour

type Claims struct {
	UserID    string `json:"uid"`
	SessionID string `json:"sid"`
	IsAdmin   bool   `json:"adm,omitempty"`
	jwt.RegisteredClaims
}

// initSecret generates a random JWT secret if one hasn't been set.
func initSecret() {
	jwtSecretMu.Lock()
	defer jwtSecretMu.Unlock()
	if jwtSecret != nil {
		return
	}
	jwtSecret = make([]byte, 64)
	if _, err := rand.Read(jwtSecret); err != nil {
		panic("failed to generate JWT secret: " + err.Error())
	}
}

// SetSecret allows setting a persistent JWT secret (e.g., from config).
// Must be called before any token operations.
func SetSecret(secret []byte) {
	jwtSecretMu.Lock()
	defer jwtSecretMu.Unlock()
	jwtSecret = secret
}

func getSecret() []byte {
	jwtSecretMu.RLock()
	defer jwtSecretMu.RUnlock()
	return jwtSecret
}

func GenerateToken(userID, sessionID string, isAdmin bool) (string, error) {
	initSecret()
	now := time.Now()
	claims := Claims{
		UserID:    userID,
		SessionID: sessionID,
		IsAdmin:   isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiry)),
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
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
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
