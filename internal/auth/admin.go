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

const (
	// Reserve 2 GB for database, OS, logs, and filesystem overhead.
	reservedBytes = 2 * 1024 * 1024 * 1024
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

// maxAllocatableBytes returns the maximum bytes that can be allocated
// based on available disk space, after subtracting the reserved buffer.
func (h *Handler) maxAllocatableBytes() int64 {
	_, avail := h.getDiskInfo()
	if avail <= reservedBytes {
		return 0
	}
	return int64(avail - reservedBytes)
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
		StorageQuota int64  `json:"storage_quota"`
		UsedBytes    int64  `json:"used_bytes"`
		CreatedAt    string `json:"created_at"`
	}

	resp := make([]userResponse, len(users))
	for i, u := range users {
		resp[i] = userResponse{
			ID:           u.ID,
			Username:     u.Username,
			IsAdmin:      u.IsAdmin,
			StorageQuota: u.StorageQuota,
			UsedBytes:    u.UsedBytes,
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
		StorageQuota int64 `json:"storage_quota"`
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
	var defaultQuota int64
	if val, err := db.GetSetting(h.DB, "default_storage_quota"); err == nil {
		defaultQuota, _ = strconv.ParseInt(val, 10, 64)
	}

	// Get the user's current effective quota.
	user, err := db.GetUserByID(h.DB, targetID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	oldEffective := user.StorageQuota
	if oldEffective <= 0 {
		oldEffective = defaultQuota
	}
	newEffective := req.StorageQuota
	if newEffective <= 0 {
		newEffective = defaultQuota
	}

	// Quotas can only be raised, never lowered.
	if newEffective < oldEffective {
		http.Error(w, "quota can only be raised, not lowered", http.StatusBadRequest)
		return
	}

	// Validate that the new total allocation fits on disk.
	currentTotal, err := db.GetTotalAllocatedQuota(h.DB, defaultQuota)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newTotal := currentTotal - oldEffective + newEffective

	maxBytes := h.maxAllocatableBytes()
	if maxBytes > 0 && newTotal > maxBytes {
		http.Error(w, "total allocated quota would exceed available disk capacity", http.StatusBadRequest)
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
	totalBytes, err := db.GetTotalStorageBytes(h.DB)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var defaultQuota int64
	if val, err := db.GetSetting(h.DB, "default_storage_quota"); err == nil {
		defaultQuota, _ = strconv.ParseInt(val, 10, 64)
	}

	totalAllocated, _ := db.GetTotalAllocatedQuota(h.DB, defaultQuota)

	// Get disk usage info from the storage layer
	diskUsed, diskAvail := h.getDiskInfo()
	maxBytes := h.maxAllocatableBytes()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"total_used_bytes":      totalBytes,
		"default_storage_quota": defaultQuota,
		"total_allocated_quota": totalAllocated,
		"max_allocatable_bytes": maxBytes,
		"disk_used_bytes":       diskUsed,
		"disk_avail_bytes":      diskAvail,
	})
}

// SetDefaultQuota sets the server-wide default storage quota (admin only).
func (h *Handler) SetDefaultQuota(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		DefaultStorageQuota int64 `json:"default_storage_quota"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.DefaultStorageQuota <= 0 {
		http.Error(w, "quota must be greater than zero", http.StatusBadRequest)
		return
	}

	// Validate that the new total allocation fits on disk.
	newTotal, err := db.GetTotalAllocatedQuota(h.DB, req.DefaultStorageQuota)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	maxBytes := h.maxAllocatableBytes()
	if maxBytes > 0 && newTotal > maxBytes {
		http.Error(w, "total allocated quota would exceed available disk capacity", http.StatusBadRequest)
		return
	}

	if err := db.SetSetting(h.DB, "default_storage_quota", strconv.FormatInt(req.DefaultStorageQuota, 10)); err != nil {
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
	defer clear(masterKey)

	kdfKey := crypto.DeriveKey(req.Password, kdfSalt)
	defer clear(kdfKey)
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
	defer clear(recoveryCode)
	recoveryMK, err := crypto.EncryptMasterKeyForRecovery(masterKey, recoveryCode, userIDBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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

	// Queue async shred — file keys already deleted from DB
	for _, mid := range mediaIDs {
		h.Shredder.QueueMedia(targetID, mid)
	}

	w.WriteHeader(http.StatusNoContent)
}
