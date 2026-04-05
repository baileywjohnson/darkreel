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

type Handler struct {
	DB      *sql.DB
	Storage interface{ RemoveMedia(userID, mediaID string) error }
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

	// Generate random master key (NOT derived from password)
	masterKey, err := crypto.GenerateFileKey() // 32 random bytes
	if err != nil {
		return "", err
	}

	// Encrypt master key with password-derived key (for login decryption)
	kdfKey := crypto.DeriveKey(password, kdfSalt)
	encryptedMK, err := crypto.EncryptBlock(masterKey, kdfKey)
	if err != nil {
		return "", err
	}

	// Encrypt master key with recovery code (for password recovery)
	recoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		return "", err
	}
	recoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, recoveryCode)
	if err != nil {
		return "", err
	}

	// Zero sensitive material
	for i := range masterKey { masterKey[i] = 0 }
	for i := range kdfKey { kdfKey[i] = 0 }

	user := &db.User{
		ID:           uuid.New().String(),
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

	// Generate random master key
	masterKey, err := crypto.GenerateFileKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Encrypt master key with password-derived key
	kdfKey := crypto.DeriveKey(req.Password, kdfSalt)
	encryptedMK, err := crypto.EncryptBlock(masterKey, kdfKey)
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
	recoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, recoveryCode)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	for i := range masterKey { masterKey[i] = 0 }
	for i := range kdfKey { kdfKey[i] = 0 }

	user := &db.User{
		ID:           uuid.New().String(),
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

	user, err := db.GetUserByUsername(h.DB, req.Username)
	if err != nil {
		http.Error(w, "Username and/or password is incorrect.", http.StatusUnauthorized)
		return
	}

	if !crypto.VerifyPassword(req.Password, user.AuthSalt, user.PasswordHash) {
		http.Error(w, "Username and/or password is incorrect.", http.StatusUnauthorized)
		return
	}

	// Decrypt master key from stored encrypted copy using password-derived key
	kdfKey := crypto.DeriveKey(req.Password, user.KDFSalt)
	masterKey, err := crypto.DecryptBlock(user.EncryptedMK, kdfKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range kdfKey { kdfKey[i] = 0 }

	sessionID := GenerateSessionID()
	Sessions.Set(sessionID, user.ID, masterKey)

	// Encrypt master key with a password-derived session key for the client.
	// Client derives the same session key via PBKDF2(password, kdfSalt)
	// and decrypts the master key. This avoids needing Argon2id in the browser.
	sessionKeyBytes := crypto.DeriveSessionKey(req.Password, user.KDFSalt)
	encMasterKey, err := crypto.EncryptBlock(masterKey, sessionKeyBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Zero local copies
	for i := range masterKey {
		masterKey[i] = 0
	}
	for i := range sessionKeyBytes {
		sessionKeyBytes[i] = 0
	}

	token, err := GenerateToken(user.ID, sessionID, user.IsAdmin)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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
	oldKdfKey := crypto.DeriveKey(req.OldPassword, user.KDFSalt)
	masterKey, err := crypto.DecryptBlock(user.EncryptedMK, oldKdfKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range oldKdfKey {
		oldKdfKey[i] = 0
	}

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
	newEncryptedMK, err := crypto.EncryptBlock(masterKey, newKdfKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range newKdfKey {
		newKdfKey[i] = 0
	}

	newPasswordHash := crypto.HashPassword(req.NewPassword, newAuthSalt)
	if err := db.UpdateUserAuth(h.DB, user.ID, newPasswordHash, newAuthSalt, newKdfSalt, newEncryptedMK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Re-encrypt master key with new session key for the client
	newSessionKey := crypto.DeriveSessionKey(req.NewPassword, newKdfSalt)
	newEncMKForClient, err := crypto.EncryptBlock(masterKey, newSessionKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range newSessionKey {
		newSessionKey[i] = 0
	}
	for i := range masterKey {
		masterKey[i] = 0
	}

	// Generate new token (session stays alive, no re-login needed)
	newToken, err := GenerateToken(user.ID, claims.SessionID, claims.IsAdmin)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":              true,
		"token":                newToken,
		"kdf_salt":             base64.StdEncoding.EncodeToString(newKdfSalt),
		"encrypted_master_key": base64.StdEncoding.EncodeToString(newEncMKForClient),
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

	// Delete all media
	mediaIDs, err := db.ListMediaIDsByUser(h.DB, user.ID)
	if err == nil {
		for _, mid := range mediaIDs {
			h.Storage.RemoveMedia(user.ID, mid)
		}
	}

	Sessions.DeleteAllForUser(user.ID)
	db.DeleteUser(h.DB, user.ID)

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

	user, err := db.GetUserByUsername(h.DB, req.Username)
	if err != nil || user.RecoveryMK == nil {
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}

	// Decode recovery code
	recoveryCode, err := base64.URLEncoding.DecodeString(req.RecoveryCode)
	if err != nil || len(recoveryCode) != 32 {
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}

	// Decrypt master key with recovery code
	masterKey, err := crypto.DecryptMasterKeyWithRecovery(user.RecoveryMK, recoveryCode)
	if err != nil {
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}

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
	newEncryptedMK, err := crypto.EncryptBlock(masterKey, newKdfKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	for i := range newKdfKey { newKdfKey[i] = 0 }

	// Update password + encrypted master key in DB
	if err := db.UpdateUserAuth(h.DB, user.ID, newPasswordHash, newAuthSalt, newKdfSalt, newEncryptedMK); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Re-encrypt recovery MK with new recovery code
	newRecoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newRecoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, newRecoveryCode)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	db.UpdateUserRecoveryMK(h.DB, user.ID, newRecoveryMK)

	// Invalidate all existing sessions for this user
	Sessions.DeleteAllForUser(user.ID)

	// Zero sensitive data
	for i := range masterKey {
		masterKey[i] = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"recovery_code": base64.URLEncoding.EncodeToString(newRecoveryCode),
	})
}
