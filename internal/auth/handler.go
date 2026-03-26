package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/google/uuid"
)

type Handler struct {
	DB *sql.DB
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
	EncryptedMasterKey string `json:"encrypted_master_key"` // master key encrypted with PBKDF2(password)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Username) < 3 || len(req.Password) < 8 {
		http.Error(w, "username must be 3+ chars, password 8+ chars", http.StatusBadRequest)
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

	user := &db.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		PasswordHash: passwordHash,
		AuthSalt:     authSalt,
		KDFSalt:      kdfSalt,
	}

	if err := db.CreateUser(h.DB, user); err != nil {
		http.Error(w, "username already taken", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": user.ID})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByUsername(h.DB, req.Username)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if !crypto.VerifyPassword(req.Password, user.AuthSalt, user.PasswordHash) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Derive master key server-side for the session (needed for directory watcher)
	masterKey := crypto.DeriveKey(req.Password, user.KDFSalt)

	sessionID := GenerateSessionID()
	Sessions.Set(sessionID, user.ID, masterKey)

	// Encrypt master key with a password-derived session key for the client.
	// Client derives the same session key via PBKDF2(password, "darkreel-session-key")
	// and decrypts the master key. This avoids needing Argon2id in the browser.
	sessionKeyBytes := crypto.DeriveSessionKey(req.Password)
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

	token, err := GenerateToken(user.ID, sessionID)
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
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	claims := GetClaims(r)
	if claims != nil {
		Sessions.Delete(claims.SessionID)
	}
	w.WriteHeader(http.StatusOK)
}
