package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	// Reserve 2 GB for database, OS, logs, and filesystem overhead.
	reservedBytes = 2 * 1024 * 1024 * 1024
)

// getDiskInfo returns (used bytes, available bytes, ok). `ok` is false if
// the syscall failed or DataDir is empty — callers must treat that as "we
// cannot prove the operation is safe" and fail closed, never as
// "unlimited capacity available".
//
// Uses golang.org/x/sys/unix.Statfs rather than the syscall package so
// the field types are consistent across linux/amd64, linux/arm64, and
// darwin (the standard syscall.Statfs_t.Bsize differs between platforms,
// which previously caused build/runtime issues on macOS).
func (h *Handler) getDiskInfo() (used uint64, avail uint64, ok bool) {
	if h.DataDir == "" {
		return 0, 0, false
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(h.DataDir, &stat); err != nil {
		return 0, 0, false
	}
	total := stat.Blocks * uint64(stat.Bsize)
	avail = stat.Bavail * uint64(stat.Bsize)
	if total < avail {
		return 0, 0, false
	}
	return total - avail, avail, true
}

// maxAllocatableBytes returns (max bytes that may be allocated, ok). When
// the disk-info probe fails (`ok=false`), callers must treat the result
// as "unknown" and refuse the quota change — fail closed. Returning 0
// with ok=true would also be safe but indistinguishable from a genuinely
// full disk.
func (h *Handler) maxAllocatableBytes() (int64, bool) {
	_, avail, ok := h.getDiskInfo()
	if !ok {
		return 0, false
	}
	if avail <= reservedBytes {
		return 0, true
	}
	return int64(avail - reservedBytes), true
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
	const gb int64 = 1 << 30
	for i, u := range users {
		// Coarsen used_bytes to nearest GB to reduce per-user activity
		// monitoring precision. Exact values remain internal for quota enforcement.
		coarsened := (u.UsedBytes / gb) * gb
		resp[i] = userResponse{
			ID:           u.ID,
			Username:     u.Username,
			IsAdmin:      u.IsAdmin,
			StorageQuota: u.StorageQuota,
			UsedBytes:    coarsened,
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

	maxBytes, ok := h.maxAllocatableBytes()
	if !ok {
		http.Error(w, "cannot determine disk capacity; refusing quota change", http.StatusServiceUnavailable)
		return
	}
	if newTotal > maxBytes {
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

	// Get disk usage info from the storage layer. When the probe fails
	// (e.g., DataDir misconfigured or Statfs unsupported), report null
	// rather than zero so the admin UI shows "unknown" instead of
	// implying "no space available".
	diskUsed, diskAvail, diskOK := h.getDiskInfo()
	maxBytes, maxOK := h.maxAllocatableBytes()

	resp := map[string]any{
		"total_used_bytes":      totalBytes,
		"default_storage_quota": defaultQuota,
		"total_allocated_quota": totalAllocated,
	}
	if diskOK {
		resp["disk_used_bytes"] = diskUsed
		resp["disk_avail_bytes"] = diskAvail
	} else {
		resp["disk_used_bytes"] = nil
		resp["disk_avail_bytes"] = nil
	}
	if maxOK {
		resp["max_allocatable_bytes"] = maxBytes
	} else {
		resp["max_allocatable_bytes"] = nil
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
	maxBytes, ok := h.maxAllocatableBytes()
	if !ok {
		http.Error(w, "cannot determine disk capacity; refusing quota change", http.StatusServiceUnavailable)
		return
	}
	if newTotal > maxBytes {
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

	// X25519 keypair + dual-wrap (master key + recovery code). Matches the
	// Register / BootstrapAdmin flow; admin-provisioned accounts get the same
	// delegation capability as self-registered accounts.
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
		PasswordHash:     crypto.HashPassword(req.Password, authSalt),
		AuthSalt:         authSalt,
		KDFSalt:          kdfSalt,
		EncryptedMK:      encryptedMK,
		RecoveryMK:       recoveryMK,
		PublicKey:        pubKey,
		EncryptedPrivKey: encryptedPrivKey,
		RecoveryPrivKey:  recoveryPrivKey,
		IsAdmin:          req.IsAdmin,
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

	if h.OnUserDeleted != nil {
		h.OnUserDeleted(targetID)
	}

	// Queue async shred — file keys already deleted from DB
	for _, mid := range mediaIDs {
		h.Shredder.QueueMedia(targetID, mid)
	}

	w.WriteHeader(http.StatusNoContent)
}
