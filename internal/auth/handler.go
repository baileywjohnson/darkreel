package auth

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	QueueMedia(userID, mediaID string) bool
}

type Handler struct {
	DB             *sql.DB
	Storage        interface{ RemoveMedia(userID, mediaID string) error }
	Shredder       MediaShredder     // async secure file deletion (used by HTTP handlers)
	AccountLimiter *AccountLimiter   // per-username limiter for login and password change
	// RecoveryLimiter is a separate per-username limiter for /recover, so
	// failed recovery attempts and failed logins don't share one budget.
	RecoveryLimiter *AccountLimiter
	DataDir        string            // data directory path (for disk usage stats)
	// OnUserDeleted is called after a user is atomically deleted so other
	// subsystems (e.g., media handler's per-user upload semaphore map) can
	// clean up user-keyed state. May be nil.
	OnUserDeleted func(userID string)
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

	// Generate the user's X25519 keypair for delegated uploads. Private key is
	// wrapped twice: once under the master key (normal unlock), and once under
	// the recovery code (forgot-password unlock). Public key is stored plaintext.
	pubKey, privKey, err := crypto.GenerateKeypair()
	if err != nil {
		return "", err
	}
	defer clear(privKey)
	encryptedPrivKey, err := crypto.EncryptBlock(privKey, masterKey, userIDBytes)
	if err != nil {
		return "", err
	}
	recoveryPrivKey, err := crypto.EncryptBlock(privKey, recoveryCode, userIDBytes)
	if err != nil {
		return "", err
	}

	user := &db.User{
		ID:               userID,
		Username:         username,
		PasswordHash:     crypto.HashPassword(password, authSalt),
		AuthSalt:         authSalt,
		KDFSalt:          kdfSalt,
		EncryptedMK:      encryptedMK,
		RecoveryMK:       recoveryMK,
		PublicKey:        pubKey,
		EncryptedPrivKey: encryptedPrivKey,
		RecoveryPrivKey:  recoveryPrivKey,
		IsAdmin:          true,
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
	// Shape 2 additions: the browser needs both to unwrap its private key
	// after deriving the master key on login. PublicKey is redundant here
	// (it's public) but bundling it saves a round-trip.
	PublicKey        string `json:"public_key"`
	EncryptedPrivKey string `json:"encrypted_priv_key"`
	IsAdmin          bool   `json:"is_admin"`
	// MustChangePassword: the account was created by an admin and must
	// choose its own password before anything else is allowed.
	MustChangePassword bool `json:"must_change_password,omitempty"`
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

	// X25519 keypair + dual-wrap (master key + recovery code).
	pubKey, privKey, err := crypto.GenerateKeypair()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clear(privKey)
	encryptedPrivKey, err := crypto.EncryptBlock(privKey, masterKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	recoveryPrivKey, err := crypto.EncryptBlock(privKey, recoveryCode, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user := &db.User{
		ID:               userID,
		Username:         req.Username,
		PasswordHash:     passwordHash,
		AuthSalt:         authSalt,
		KDFSalt:          kdfSalt,
		EncryptedMK:      encryptedMK,
		RecoveryMK:       recoveryMK,
		PublicKey:        pubKey,
		EncryptedPrivKey: encryptedPrivKey,
		RecoveryPrivKey:  recoveryPrivKey,
	}

	if err := db.CreateUser(h.DB, user); err != nil {
		http.Error(w, "Registration failed.", http.StatusConflict)
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
	// (including non-existent) to avoid leaking account existence: the budget,
	// the 429 and its message are the same either way.
	if h.AccountLimiter != nil && !h.AccountLimiter.Allow(req.Username) {
		http.Error(w, AccountLockedMessage, http.StatusTooManyRequests)
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
	if h.AccountLimiter != nil {
		h.AccountLimiter.Succeeded(req.Username)
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

	// A password change or recovery that committed after the user row was
	// read above has retired the keys this response would hand out. Rotation
	// drops the user's sessions after it commits, so a key still unchanged
	// now means that drop hasn't happened yet and will cover this session.
	if cur, err := db.GetUserPublicKey(h.DB, user.ID); err != nil || !bytes.Equal(cur, user.PublicKey) {
		Sessions.Delete(sessionID)
		http.Error(w, "Username and/or password is incorrect.", http.StatusUnauthorized)
		return
	}

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

	mustChange, err := db.MustChangePassword(h.DB, user.ID)
	if err != nil {
		Sessions.Delete(sessionID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if mustChange {
		Sessions.MarkMustChangePassword(sessionID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginResponse{
		Token:              token,
		KDFSalt:            base64.StdEncoding.EncodeToString(user.KDFSalt),
		UserID:             user.ID,
		EncryptedMasterKey: base64.StdEncoding.EncodeToString(encMasterKey),
		PublicKey:          base64.StdEncoding.EncodeToString(user.PublicKey),
		EncryptedPrivKey:   base64.StdEncoding.EncodeToString(user.EncryptedPrivKey),
		IsAdmin:            user.IsAdmin,
		MustChangePassword: mustChange,
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

	// Per-account rate limit: defends against brute-force of the old password
	// via a stolen JWT. Every attempt is counted before verification (so
	// parallel guesses can't race past it); a correct one is refunded.
	if h.AccountLimiter != nil && !h.AccountLimiter.Allow(user.Username) {
		http.Error(w, AccountLockedMessage, http.StatusTooManyRequests)
		return
	}

	if !crypto.VerifyPassword(req.OldPassword, user.AuthSalt, user.PasswordHash) {
		http.Error(w, "Current password is incorrect.", http.StatusBadRequest)
		return
	}
	if h.AccountLimiter != nil {
		h.AccountLimiter.Succeeded(user.Username)
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

	// Replace the master key, keypair and recovery code, and re-seal every
	// item to the new public key (see rotate.go).
	rot, err := prepareKeyRotation(h.DB, user, masterKey, req.NewPassword)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rot.wipe()

	// Compute the new session key, client-wrapped master key, and new JWT
	// BEFORE opening the DB transaction. These are in-memory crypto ops that
	// can in principle fail (rand.Read, JWT signing) — if any of them fails
	// AFTER commit, the password change would be durable on disk but the
	// client sees HTTP 500, retries with the old password, and gets locked
	// out by the account rate limiter. Computing up front means any failure
	// aborts the request cleanly with no DB mutation.
	newSessionID := GenerateSessionID()
	newSessionKey := crypto.DeriveSessionKey(req.NewPassword, rot.keys.KDFSalt)
	defer clear(newSessionKey)
	newEncMKForClient, err := crypto.EncryptBlock(rot.newMK, newSessionKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newToken, err := GenerateToken(user.ID, newSessionID, user.IsAdmin)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Sessions are dropped while the write lock is held (and again after
	// commit): a request authenticated with one of them could otherwise start
	// after the commit and write data encrypted to the retired keys.
	err = rot.commit(h.DB, func() { Sessions.DeleteAllForUser(user.ID) })
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "user no longer exists", http.StatusNotFound)
		return
	}
	if errors.Is(err, db.ErrKeysChanged) {
		http.Error(w, "Your account keys were changed by another request. Sign in again and retry.", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	recoveryCodeB64 := base64.URLEncoding.EncodeToString(rot.recoveryCode)

	// Post-commit: only in-memory SessionStore ops. These cannot fail. The
	// session holds no master key; the client gets it wrapped below.
	Sessions.DeleteAllForUser(user.ID)
	Sessions.Set(newSessionID, user.ID, nil)

	// The client must replace its master key AND its keypair from this
	// response: every item is now sealed to the new public key, and uploads
	// sealed to the old one would be undecryptable.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":              true,
		"token":                newToken,
		"kdf_salt":             base64.StdEncoding.EncodeToString(rot.keys.KDFSalt),
		"encrypted_master_key": base64.StdEncoding.EncodeToString(newEncMKForClient),
		"public_key":           base64.StdEncoding.EncodeToString(rot.keys.PublicKey),
		"encrypted_priv_key":   base64.StdEncoding.EncodeToString(rot.keys.EncryptedPrivKey),
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

	if h.OnUserDeleted != nil {
		h.OnUserDeleted(user.ID)
	}

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

	// Per-username rate limit (same rationale as Login), with its own budget
	// so failed logins and failed recoveries don't lock each other out.
	if h.RecoveryLimiter != nil && !h.RecoveryLimiter.Allow(req.Username) {
		http.Error(w, AccountLockedMessage, http.StatusTooManyRequests)
		return
	}

	// A nonexistent username and a wrong recovery code must be
	// indistinguishable, including by timing. Both paths do exactly one
	// AES-GCM open of a master-key-sized blob and nothing else (previously
	// the unknown-user path ran a dummy Argon2id while a wrong code failed in
	// microseconds). Undecodable codes are replaced by a dummy of the right
	// size so they take the same path.
	recoveryCode, decodeErr := base64.URLEncoding.DecodeString(req.RecoveryCode)
	if decodeErr != nil || len(recoveryCode) != 32 {
		recoveryCode = make([]byte, 32)
	}
	defer clear(recoveryCode)

	user, err := db.GetUserByUsername(h.DB, req.Username)
	userFound := err == nil && user.RecoveryMK != nil
	wrappedMK, aad := dummyRecoveryMK, dummyRecoveryAAD
	if userFound {
		wrappedMK, aad = user.RecoveryMK, []byte(user.ID)
	}
	masterKey, err := crypto.DecryptMasterKeyWithRecovery(wrappedMK, recoveryCode, aad)
	if !userFound || decodeErr != nil || err != nil {
		clear(masterKey)
		http.Error(w, "Username and/or recovery code is incorrect.", http.StatusBadRequest)
		return
	}
	defer clear(masterKey)
	if h.RecoveryLimiter != nil {
		h.RecoveryLimiter.Succeeded(req.Username)
	}

	// Replace the master key, keypair and recovery code, and re-seal every
	// item to the new public key (see rotate.go). The recovery code that was
	// just used unwraps only the retired keys.
	rot, err := prepareKeyRotation(h.DB, user, masterKey, req.NewPassword)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rot.wipe()

	err = rot.commit(h.DB, func() { Sessions.DeleteAllForUser(user.ID) })
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "user no longer exists", http.StatusNotFound)
		return
	}
	if errors.Is(err, db.ErrKeysChanged) {
		http.Error(w, "Your account keys were changed by another request. Try again.", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Invalidate all existing sessions for this user
	Sessions.DeleteAllForUser(user.ID)

	recoveryCodeB64 := base64.URLEncoding.EncodeToString(rot.recoveryCode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"recovery_code": recoveryCodeB64,
	})
}

// dummyRecoveryMK stands in for a user's recovery-wrapped master key when the
// username doesn't exist: nonce(12) + key(32) + tag(16), random so it never
// decrypts. dummyRecoveryAAD has the length of a real user ID (a UUID).
var (
	dummyRecoveryMK  = mustRandom(12 + 32 + 16)
	dummyRecoveryAAD = []byte("00000000-0000-0000-0000-000000000000")
)

func mustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}
