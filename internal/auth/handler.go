package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/google/uuid"
)

func isStrongPassword(pw string) bool {
	if len(pw) < 16 || len(pw) > 128 {
		return false
	}
	hasLetter, hasDigit, hasSymbol := false, false, false
	for _, c := range pw {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetter = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			return false // spaces not allowed
		default:
			hasSymbol = true
		}
	}
	return hasLetter && hasDigit && hasSymbol
}

func isValidUsername(u string) bool {
	if len(u) < 3 || len(u) > 64 {
		return false
	}
	for _, c := range u {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// MediaShredder queues media directories for background secure deletion.
type MediaShredder interface {
	QueueMedia(userID, mediaID string)
}

type Handler struct {
	DB             *sql.DB
	Storage        interface{ RemoveMedia(userID, mediaID string) error }
	Shredder       MediaShredder     // async secure file deletion (used by HTTP handlers)
	AccountLimiter *AccountLimiter   // per-username rate limiter for login/recovery
	DataDir        string            // data directory path (for disk usage stats)
}

// BootstrapAdmin creates the initial admin user if no users exist.
// Returns the recovery code (base64url-encoded) so it can be logged.
func BootstrapAdmin(database *sql.DB, username, password string) (string, error) {
	if !isStrongPassword(password) {
		return "", fmt.Errorf("DARKREEL_ADMIN_PASSWORD must be 16+ characters with at least one letter, one number, and one symbol")
	}
	if len(username) < 3 || len(username) > 64 {
		return "", fmt.Errorf("DARKREEL_ADMIN_USERNAME must be 3-64 characters")
	}

	authSalt, err := crypto.GenerateSalt()
	if err != nil {
		return "", err
	}
	kdfSalt, err := crypto.GenerateSalt()
	if err != nil {
		return "", err
	}

	// Generate user ID first — needed as AAD for master key encryption
	userID := uuid.New().String()
	userIDBytes := []byte(userID)

	// Generate random master key (NOT derived from password)
	masterKey, err := crypto.GenerateFileKey() // 32 random bytes
	if err != nil {
		return "", err
	}
	defer clear(masterKey)

	// Encrypt master key with password-derived key (for login decryption)
	kdfKey := crypto.DeriveKey(password, kdfSalt)
	defer clear(kdfKey)
	encryptedMK, err := crypto.EncryptBlock(masterKey, kdfKey, userIDBytes)
	if err != nil {
		return "", err
	}

	// Encrypt master key with recovery code (for password recovery)
	recoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		return "", err
	}
	defer clear(recoveryCode)
	recoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, recoveryCode, userIDBytes)
	if err != nil {
		return "", err
	}

	user := &db.User{
		ID:           userID,
		Username:     username,
		PasswordHash: crypto.HashPassword(password, authSalt),
		AuthSalt:     authSalt,
		KDFSalt:      kdfSalt,
		EncryptedMK:  encryptedMK,
		RecoveryMK:   recoveryMK,
		IsAdmin:      true,
	}

	if err := db.CreateUser(database, user); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(recoveryCode), nil
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token              string `json:"token"`
	KDFSalt            string `json:"kdf_salt"`
	UserID             string `json:"user_id"`
	EncryptedMasterKey string `json:"encrypted_master_key"`
	IsAdmin            bool   `json:"is_admin"`
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !isValidUsername(req.Username) {
		http.Error(w, "username must be 3-64 alphanumeric characters", http.StatusBadRequest)
		return
	}
	if !isStrongPassword(req.Password) {
		http.Error(w, "password must be 16-128 characters with at least one letter, one number, and one symbol", http.StatusBadRequest)
		return
	}

	authSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	kdfSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	passwordHash := crypto.HashPassword(req.Password, authSalt)

	// Generate user ID first — needed as AAD for master key encryption
	userID := uuid.New().String()
	userIDBytes := []byte(userID)

	// Generate random master key
	masterKey, err := crypto.GenerateFileKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(masterKey)

	// Encrypt master key with password-derived key
	kdfKey := crypto.DeriveKey(req.Password, kdfSalt)
	defer clear(kdfKey)
	encryptedMK, err := crypto.EncryptBlock(masterKey, kdfKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Encrypt master key with recovery code
	recoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(recoveryCode)
	recoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, recoveryCode, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user := &db.User{
		ID:           userID,
		Username:     req.Username,
		PasswordHash: passwordHash,
		AuthSalt:     authSalt,
		KDFSalt:      kdfSalt,
		EncryptedMK:  encryptedMK,
		RecoveryMK:   recoveryMK,
	}

	if err := db.CreateUser(h.DB, user); err != nil {
		http.Error(w, "Username is unavailable.", http.StatusConflict)
		return
	}

	// Return recovery code — this is the ONLY time it's shown
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id":            user.ID,
		"recovery_code": base64.URLEncoding.EncodeToString(recoveryCode),
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64 KB
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Per-username rate limit: prevents distributed brute-force against a single
	// account even when per-IP limits are bypassed. Checked for all usernames
	// (including non-existent) to avoid leaking account existence via timing.
	if h.AccountLimiter != nil && !h.AccountLimiter.Allow(req.Username) {
		// Still perform dummy work so response timing is indistinguishable
		dummySalt, _ := crypto.GenerateSalt()
		crypto.DeriveKey(req.Password, dummySalt)
		http.Error(w, "Username and/or password is incorrect.", http.StatusUnauthorized)
		return
	}

	user, err := db.GetUserByUsername(h.DB, req.Username)
	if err != nil {
		// Perform dummy derivation to prevent timing-based username enumeration.
		// Without this, "user not found" returns faster than "wrong password".
		// Use random salt so timing matches real Argon2id operations.
		dummySalt, _ := crypto.GenerateSalt()
		crypto.DeriveKey(req.Password, dummySalt)
		http.Error(w, "Username and/or password is incorrect.", http.StatusUnauthorized)
		return
	}

	if !crypto.VerifyPassword(req.Password, user.AuthSalt, user.PasswordHash) {
		http.Error(w, "Username and/or password is incorrect.", http.StatusUnauthorized)
		return
	}

	// Decrypt master key from stored encrypted copy using password-derived key
	userIDBytes := []byte(user.ID)
	kdfKey := crypto.DeriveKey(req.Password, user.KDFSalt)
	defer clear(kdfKey)
	masterKey, err := crypto.DecryptBlock(user.EncryptedMK, kdfKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(masterKey)

	sessionID := GenerateSessionID()
	Sessions.Set(sessionID, user.ID, masterKey)

	// Encrypt master key with a password-derived session key for the client.
	// Client derives the same session key via PBKDF2(password, kdfSalt)
	// and decrypts the master key. This avoids needing Argon2id in the browser.
	sessionKeyBytes := crypto.DeriveSessionKey(req.Password, user.KDFSalt)
	defer clear(sessionKeyBytes)
	encMasterKey, err := crypto.EncryptBlock(masterKey, sessionKeyBytes, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token, err := GenerateToken(user.ID, sessionID, user.IsAdmin)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Master key has been re-encrypted for the client — clear it from the
	// session immediately. The session entry itself stays alive for auth
	// (Sessions.Has), but the plaintext key is no longer in memory.
	Sessions.ClearKey(sessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{
		Token:              token,
		KDFSalt:            base64.StdEncoding.EncodeToString(user.KDFSalt),
		UserID:             user.ID,
		EncryptedMasterKey: base64.StdEncoding.EncodeToString(encMasterKey),
		IsAdmin:            user.IsAdmin,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r)
	if claims != nil {
		Sessions.Delete(claims.SessionID)
	}
	w.WriteHeader(http.StatusOK)
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	claims := GetClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !isStrongPassword(req.NewPassword) {
		http.Error(w, "password must be 16-128 characters with at least one letter, one number, and one symbol", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByID(h.DB, claims.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if !crypto.VerifyPassword(req.OldPassword, user.AuthSalt, user.PasswordHash) {
		http.Error(w, "Current password is incorrect.", http.StatusBadRequest)
		return
	}

	// Decrypt master key with old password
	userIDBytes := []byte(user.ID)
	oldKdfKey := crypto.DeriveKey(req.OldPassword, user.KDFSalt)
	defer clear(oldKdfKey)
	masterKey, err := crypto.DecryptBlock(user.EncryptedMK, oldKdfKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(masterKey)

	// Re-encrypt master key with new password
	newAuthSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newKdfSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newKdfKey := crypto.DeriveKey(req.NewPassword, newKdfSalt)
	defer clear(newKdfKey)
	newEncryptedMK, err := crypto.EncryptBlock(masterKey, newKdfKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newPasswordHash := crypto.HashPassword(req.NewPassword, newAuthSalt)

	// Rotate recovery code so old recovery codes are invalidated on password change
	newRecoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(newRecoveryCode)
	newRecoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, newRecoveryCode, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if err := db.UpdateUserAuthTx(tx, user.ID, newPasswordHash, newAuthSalt, newKdfSalt, newEncryptedMK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := db.UpdateUserRecoveryMKTx(tx, user.ID, newRecoveryMK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	recoveryCodeB64 := base64.URLEncoding.EncodeToString(newRecoveryCode)

	// Invalidate all existing sessions (including attacker sessions)
	Sessions.DeleteAllForUser(user.ID)

	// Create a fresh session for the current user
	newSessionID := GenerateSessionID()
	Sessions.Set(newSessionID, user.ID, masterKey)

	// Re-encrypt master key with new session key for the client
	newSessionKey := crypto.DeriveSessionKey(req.NewPassword, newKdfSalt)
	defer clear(newSessionKey)
	newEncMKForClient, err := crypto.EncryptBlock(masterKey, newSessionKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Generate new token with fresh session ID (use DB admin status, not stale JWT claim)
	newToken, err := GenerateToken(user.ID, newSessionID, user.IsAdmin)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Master key re-encrypted for client — clear from session immediately
	Sessions.ClearKey(newSessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":              true,
		"token":                newToken,
		"kdf_salt":             base64.StdEncoding.EncodeToString(newKdfSalt),
		"encrypted_master_key": base64.StdEncoding.EncodeToString(newEncMKForClient),
		"recovery_code":        recoveryCodeB64,
	})
}

func (h *Handler) DeleteOwnAccount(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	claims := GetClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByID(h.DB, claims.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if !crypto.VerifyPassword(req.Password, user.AuthSalt, user.PasswordHash) {
		http.Error(w, "password is incorrect", http.StatusBadRequest)
		return
	}

	// Collect media IDs before deletion so we can shred files after.
	mediaIDs, _ := db.ListMediaIDsByUser(h.DB, user.ID)

	// Atomic delete: checks admin count inside a transaction to prevent TOCTOU.
	// DB record is deleted first — orphan cleanup at startup handles leftover files.
	if err := db.DeleteUserAtomic(h.DB, user.ID); err != nil {
		if err.Error() == "cannot delete the last admin account" {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	Sessions.DeleteAllForUser(user.ID)

	// Queue async shred — file keys are already deleted from DB,
	// making encrypted data unrecoverable. Startup orphan cleanup
	// handles any leftovers if the server crashes before shredding.
	for _, mid := range mediaIDs {
		h.Shredder.QueueMedia(user.ID, mid)
	}

	w.WriteHeader(http.StatusNoContent)
}

type recoveryRequest struct {
	Username     string `json:"username"`
	RecoveryCode string `json:"recovery_code"` // base64url-encoded
	NewPassword  string `json:"new_password"`
}

// Recover resets a user's password using their recovery code.
func (h *Handler) Recover(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req recoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !isStrongPassword(req.NewPassword) {
		http.Error(w, "password must be 16-128 characters with at least one letter, one number, and one symbol", http.StatusBadRequest)
		return
	}

	// Per-username rate limit (same rationale as Login)
	if h.AccountLimiter != nil && !h.AccountLimiter.Allow(req.Username) {
		dummySalt, _ := crypto.GenerateSalt()
		crypto.DeriveKey(req.NewPassword, dummySalt)
		dummyCiphertext := make([]byte, 60)
		crypto.DecryptMasterKeyWithRecovery(dummyCiphertext, make([]byte, 32), []byte("dummy"))
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByUsername(h.DB, req.Username)
	if err != nil || user.RecoveryMK == nil {
		// Perform dummy derivation + decryption to prevent timing-based username enumeration.
		// Without this, "user not found" returns faster than "wrong recovery code".
		dummySalt, _ := crypto.GenerateSalt()
		crypto.DeriveKey(req.NewPassword, dummySalt)
		dummyCiphertext := make([]byte, 60) // realistic ciphertext length
		crypto.DecryptMasterKeyWithRecovery(dummyCiphertext, make([]byte, 32), []byte("dummy"))
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}

	// Decode recovery code — always attempt decryption to prevent timing leaks.
	// If decode fails, use a dummy code so the decrypt call takes the same time.
	recoveryCode, decodeErr := base64.URLEncoding.DecodeString(req.RecoveryCode)
	if decodeErr != nil || len(recoveryCode) != 32 {
		recoveryCode = make([]byte, 32) // dummy code for constant-time path
	}

	// Decrypt master key with recovery code
	userIDBytes := []byte(user.ID)
	masterKey, err := crypto.DecryptMasterKeyWithRecovery(user.RecoveryMK, recoveryCode, userIDBytes)
	clear(recoveryCode)
	if decodeErr != nil || err != nil {
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}
	defer clear(masterKey)

	// Generate new auth/KDF salts and hash
	newAuthSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newKdfSalt, err := crypto.GenerateSalt()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newPasswordHash := crypto.HashPassword(req.NewPassword, newAuthSalt)

	// Re-encrypt master key with new password-derived key
	newKdfKey := crypto.DeriveKey(req.NewPassword, newKdfSalt)
	defer clear(newKdfKey)
	newEncryptedMK, err := crypto.EncryptBlock(masterKey, newKdfKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Re-encrypt recovery MK with new recovery code
	newRecoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(newRecoveryCode)
	newRecoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, newRecoveryCode, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update auth and recovery MK atomically
	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if err := db.UpdateUserAuthTx(tx, user.ID, newPasswordHash, newAuthSalt, newKdfSalt, newEncryptedMK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := db.UpdateUserRecoveryMKTx(tx, user.ID, newRecoveryMK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Invalidate all existing sessions for this user
	Sessions.DeleteAllForUser(user.ID)

	recoveryCodeB64 := base64.URLEncoding.EncodeToString(newRecoveryCode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"recovery_code": recoveryCodeB64,
	})
}
