package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"syscall"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// getDiskInfo returns (used bytes, available bytes) for the data directory.
func (h *Handler) getDiskInfo() (uint64, uint64) {
	if h.DataDir == "" {
		return 0, 0
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(h.DataDir, &stat); err != nil {
		return 0, 0
	}
	total := stat.Blocks * uint64(stat.Bsize)
	avail := stat.Bavail * uint64(stat.Bsize)
	used := total - avail
	return used, avail
}

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

// ListUsers returns all users with usage stats (admin only).
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := db.ListUsersWithUsage(h.DB)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	type userResponse struct {
		ID           string `json:"id"`
		Username     string `json:"username"`
		IsAdmin      bool   `json:"is_admin"`
		StorageQuota int    `json:"storage_quota"`
		ChunkCount   int    `json:"chunk_count"`
		CreatedAt    string `json:"created_at"`
	}

	resp := make([]userResponse, len(users))
	for i, u := range users {
		resp[i] = userResponse{
			ID:           u.ID,
			Username:     u.Username,
			IsAdmin:      u.IsAdmin,
			StorageQuota: u.StorageQuota,
			ChunkCount:   u.ChunkCount,
			CreatedAt:    u.CreatedAt,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// SetUserQuota sets a per-user storage quota override (admin only).
// The quota can only be raised above the server default, not lowered.
func (h *Handler) SetUserQuota(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "id")
	if _, err := uuid.Parse(targetID); err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		StorageQuota int `json:"storage_quota"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.StorageQuota < 0 {
		http.Error(w, "quota must be non-negative", http.StatusBadRequest)
		return
	}

	// Get server default quota
	defaultQuota := 0
	if val, err := db.GetSetting(h.DB, "default_storage_quota"); err == nil {
		defaultQuota, _ = strconv.Atoi(val)
	}

	// Quota can only be raised above the server default (or set to 0 to use default)
	if req.StorageQuota != 0 && defaultQuota > 0 && req.StorageQuota < defaultQuota {
		http.Error(w, "per-user quota cannot be lower than the server default", http.StatusBadRequest)
		return
	}

	if err := db.UpdateUserQuota(h.DB, targetID, req.StorageQuota); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetStorageStats returns total storage statistics (admin only).
func (h *Handler) GetStorageStats(w http.ResponseWriter, r *http.Request) {
	totalChunks, err := db.GetTotalChunkCount(h.DB)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	defaultQuota := 0
	if val, err := db.GetSetting(h.DB, "default_storage_quota"); err == nil {
		defaultQuota, _ = strconv.Atoi(val)
	}

	// Get disk usage info from the storage layer
	diskUsed, diskAvail := h.getDiskInfo()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total_chunks":         totalChunks,
		"default_storage_quota": defaultQuota,
		"disk_used_bytes":      diskUsed,
		"disk_avail_bytes":     diskAvail,
	})
}

// SetDefaultQuota sets the server-wide default storage quota (admin only).
func (h *Handler) SetDefaultQuota(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		DefaultStorageQuota int `json:"default_storage_quota"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DefaultStorageQuota < 0 {
		http.Error(w, "quota must be non-negative", http.StatusBadRequest)
		return
	}

	if err := db.SetSetting(h.DB, "default_storage_quota", strconv.Itoa(req.DefaultStorageQuota)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
	if _, err := uuid.Parse(targetID); err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	claims := GetClaims(r)

	if claims != nil && claims.UserID == targetID {
		http.Error(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}

	// Collect media IDs before deletion so we can shred files after.
	mediaIDs, _ := db.ListMediaIDsByUser(h.DB, targetID)

	// Atomic delete: checks admin count inside a transaction to prevent TOCTOU
	// race where two admins concurrently delete each other, leaving zero admins.
	// Also deletes the DB record first — if the server crashes between DB delete
	// and file shred, orphan cleanup at next startup handles the leftover files.
	if err := db.DeleteUserAtomic(h.DB, targetID); err != nil {
		if err.Error() == "cannot delete the last admin account" {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, "user not found", http.StatusNotFound)
		}
		return
	}

	Sessions.DeleteAllForUser(targetID)

	// Shred files after DB deletion (orphan cleanup handles crashes here)
	for _, mid := range mediaIDs {
		h.Storage.RemoveMedia(targetID, mid)
	}

	w.WriteHeader(http.StatusNoContent)
}
