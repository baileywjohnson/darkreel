package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024 // 64 MB
	ArgonThreads = 4
	ArgonKeyLen  = 32
	SaltLen      = 32
)

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 256-bit key from a password and salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// HashPassword returns a base64-encoded Argon2id hash for authentication.
func HashPassword(password string, salt []byte) string {
	hash := DeriveKey(password, salt)
	return base64.StdEncoding.EncodeToString(hash)
}

// VerifyPassword checks if a password matches the stored hash.
func VerifyPassword(password string, salt []byte, storedHash string) bool {
	computed := HashPassword(password, salt)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// GenerateFileKey generates a random 256-bit file encryption key.
func GenerateFileKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate file key: %w", err)
	}
	return key, nil
}

// EncryptKey encrypts a file key with the user's master key using AES-256-GCM.
func EncryptKey(fileKey, masterKey []byte) ([]byte, error) {
	return EncryptBlock(fileKey, masterKey)
}

// DecryptKey decrypts a file key with the user's master key.
func DecryptKey(encryptedKey, masterKey []byte) ([]byte, error) {
	return DecryptBlock(encryptedKey, masterKey)
}

// DeriveSessionKey derives a 256-bit key using PBKDF2 with SHA-256.
// Uses the user's KDF salt for per-user key isolation.
// This matches the client-side Web Crypto PBKDF2 derivation.
func DeriveSessionKey(password string, kdfSalt []byte) []byte {
	return pbkdf2.Key([]byte(password), kdfSalt, 600000, 32, sha256.New)
}

// GenerateRecoveryCode generates a random 256-bit recovery code.
// Returns the raw bytes (32 bytes) — encode as hex or base64 for display.
func GenerateRecoveryCode() ([]byte, error) {
	code := make([]byte, 32)
	if _, err := rand.Read(code); err != nil {
		return nil, fmt.Errorf("generate recovery code: %w", err)
	}
	return code, nil
}

// EncryptMasterKeyForRecovery encrypts the master key with a recovery code.
func EncryptMasterKeyForRecovery(masterKey, recoveryCode []byte) ([]byte, error) {
	return EncryptBlock(masterKey, recoveryCode)
}

// DecryptMasterKeyWithRecovery decrypts the master key using a recovery code.
func DecryptMasterKeyWithRecovery(encryptedMK, recoveryCode []byte) ([]byte, error) {
	return DecryptBlock(encryptedMK, recoveryCode)
}
