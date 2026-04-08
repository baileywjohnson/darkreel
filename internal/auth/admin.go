package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// AdminMiddleware returns middleware that verifies admin status from the database
// on every request, so revoked admin privileges take effect immediately.
func AdminMiddleware(database *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetClaims(r)
			if claims == nil {
				http.Error(w, "admin access required", http.StatusForbidden)
				return
			}
			user, err := db.GetUserByID(database, claims.UserID)
			if err != nil || !user.IsAdmin {
				http.Error(w, "admin access required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ListUsers returns all users (admin only).
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := db.ListUsers(h.DB)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type userResponse struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		IsAdmin   bool   `json:"is_admin"`
		CreatedAt string `json:"created_at"`
	}

	resp := make([]userResponse, len(users))
	for i, u := range users {
		resp[i] = userResponse{
			ID:        u.ID,
			Username:  u.Username,
			IsAdmin:   u.IsAdmin,
			CreatedAt: u.CreatedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

// CreateUser creates a new user (admin only).
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req createUserRequest
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

	// Generate user ID first — needed as AAD for master key encryption
	userID := uuid.New().String()
	userIDBytes := []byte(userID)

	masterKey, err := crypto.GenerateFileKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	kdfKey := crypto.DeriveKey(req.Password, kdfSalt)
	encryptedMK, err := crypto.EncryptBlock(masterKey, kdfKey, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	recoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	recoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, recoveryCode, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	for i := range masterKey {
		masterKey[i] = 0
	}
	for i := range kdfKey {
		kdfKey[i] = 0
	}
	defer func() { for i := range recoveryCode { recoveryCode[i] = 0 } }()

	user := &db.User{
		ID:           userID,
		Username:     req.Username,
		PasswordHash: crypto.HashPassword(req.Password, authSalt),
		AuthSalt:     authSalt,
		KDFSalt:      kdfSalt,
		EncryptedMK:  encryptedMK,
		RecoveryMK:   recoveryMK,
		IsAdmin:      req.IsAdmin,
	}

	if err := db.CreateUser(h.DB, user); err != nil {
		http.Error(w, "Username is unavailable.", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"id":            user.ID,
		"username":      user.Username,
		"recovery_code": base64.URLEncoding.EncodeToString(recoveryCode),
	})
}

// DeleteUser deletes a user and all their media (admin only).
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	claims := GetClaims(r)

	if claims != nil && claims.UserID == targetID {
		http.Error(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}

	// Delete all media for this user
	mediaIDs, err := db.ListMediaIDsByUser(h.DB, targetID)
	if err == nil {
		for _, mid := range mediaIDs {
			h.Storage.RemoveMedia(targetID, mid)
		}
	}

	// Invalidate sessions
	Sessions.DeleteAllForUser(targetID)

	if err := db.DeleteUser(h.DB, targetID); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
