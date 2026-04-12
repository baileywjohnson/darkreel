package db

import (
	"database/sql"
	"fmt"
)

type User struct {
	ID           string
	Username     string
	PasswordHash string
	AuthSalt     []byte
	KDFSalt      []byte
	EncryptedMK  []byte // master key encrypted with KDF-derived key
	RecoveryMK   []byte // master key encrypted with recovery code
	IsAdmin      bool
	StorageQuota int64 // per-user storage quota in bytes (0 = use server default)
	CreatedAt    string
}

func CreateUser(db *sql.DB, u *User) error {
	isAdmin := 0
	if u.IsAdmin {
		isAdmin = 1
	}
	_, err := db.Exec(
		`INSERT INTO users (id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk, is_admin, storage_quota, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y', 'now'))`,
		u.ID, u.Username, u.PasswordHash, u.AuthSalt, u.KDFSalt, u.EncryptedMK, u.RecoveryMK, isAdmin, u.StorageQuota,
	)
	return err
}

// UserWithUsage extends User with storage usage for admin display.
type UserWithUsage struct {
	User
	ChunkCount int
	UsedBytes  int64
}

func ListUsersWithUsage(db *sql.DB) ([]UserWithUsage, error) {
	rows, err := db.Query(`
		SELECT u.id, u.username, u.is_admin, u.storage_quota, u.created_at,
		       COALESCE(SUM(m.chunk_count), 0) AS chunk_count,
		       COALESCE(SUM(m.size_bytes), 0) AS used_bytes
		FROM users u
		LEFT JOIN media m ON m.user_id = u.id
		GROUP BY u.id
		ORDER BY u.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []UserWithUsage
	for rows.Next() {
		var uu UserWithUsage
		var isAdmin int
		if err := rows.Scan(&uu.ID, &uu.Username, &isAdmin, &uu.StorageQuota, &uu.CreatedAt, &uu.ChunkCount, &uu.UsedBytes); err != nil {
			return nil, err
		}
		uu.IsAdmin = isAdmin != 0
		users = append(users, uu)
	}
	return users, rows.Err()
}

func ListUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query(`SELECT id, username, is_admin, storage_quota, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var isAdmin int
		if err := rows.Scan(&u.ID, &u.Username, &isAdmin, &u.StorageQuota, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.IsAdmin = isAdmin != 0
		users = append(users, u)
	}
	return users, rows.Err()
}

func DeleteUser(db *sql.DB, userID string) error {
	_, err := db.Exec(`DELETE FROM users WHERE id = ?`, userID)
	return err
}

// DeleteUserAtomic deletes a user inside a transaction.
// If the user is an admin, it re-checks the admin count to prevent deleting
// the last admin (TOCTOU protection against concurrent deletions).
func DeleteUserAtomic(database *sql.DB, userID string) error {
	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check if target is admin
	var isAdmin int
	err = tx.QueryRow(`SELECT is_admin FROM users WHERE id = ?`, userID).Scan(&isAdmin)
	if err != nil {
		return err
	}

	if isAdmin != 0 {
		var adminCount int
		err = tx.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&adminCount)
		if err != nil {
			return err
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot delete the last admin account")
		}
	}

	_, err = tx.Exec(`DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func UpdateUserRecoveryMK(db *sql.DB, userID string, recoveryMK []byte) error {
	_, err := db.Exec(`UPDATE users SET recovery_mk = ? WHERE id = ?`, recoveryMK, userID)
	return err
}

func UpdateUserRecoveryMKTx(tx *sql.Tx, userID string, recoveryMK []byte) error {
	_, err := tx.Exec(`UPDATE users SET recovery_mk = ? WHERE id = ?`, recoveryMK, userID)
	return err
}

func UpdateUserAuth(db *sql.DB, userID, passwordHash string, authSalt, kdfSalt, encryptedMK []byte) error {
	_, err := db.Exec(
		`UPDATE users SET password_hash = ?, auth_salt = ?, kdf_salt = ?, encrypted_mk = ? WHERE id = ?`,
		passwordHash, authSalt, kdfSalt, encryptedMK, userID,
	)
	return err
}

func UpdateUserAuthTx(tx *sql.Tx, userID, passwordHash string, authSalt, kdfSalt, encryptedMK []byte) error {
	_, err := tx.Exec(
		`UPDATE users SET password_hash = ?, auth_salt = ?, kdf_salt = ?, encrypted_mk = ? WHERE id = ?`,
		passwordHash, authSalt, kdfSalt, encryptedMK, userID,
	)
	return err
}

func GetUserCount(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func GetAdminCount(db *sql.DB) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE is_admin = 1`).Scan(&count)
	return count, err
}

func ListUserIDs(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT id FROM users`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	u := &User{}
	var isAdmin int
	err := db.QueryRow(
		`SELECT id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk, is_admin, storage_quota, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.EncryptedMK, &u.RecoveryMK, &isAdmin, &u.StorageQuota, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	return u, nil
}

func GetUserByID(db *sql.DB, id string) (*User, error) {
	u := &User{}
	var isAdmin int
	err := db.QueryRow(
		`SELECT id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk, is_admin, storage_quota, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.EncryptedMK, &u.RecoveryMK, &isAdmin, &u.StorageQuota, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	return u, nil
}

// UpdateUserQuota sets a per-user storage quota override (in bytes).
// Quota must be >= current server default or 0 (meaning use server default).
func UpdateUserQuota(db *sql.DB, userID string, quota int64) error {
	_, err := db.Exec(`UPDATE users SET storage_quota = ? WHERE id = ?`, quota, userID)
	return err
}

// GetTotalStorageBytes returns the total stored bytes across all users.
func GetTotalStorageBytes(db *sql.DB) (int64, error) {
	var total int64
	err := db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM media`).Scan(&total)
	return total, err
}

// GetTotalAllocatedQuota returns the sum of effective quotas (in bytes) across all users.
// Users with a per-user override use that value; others use the provided default.
func GetTotalAllocatedQuota(db *sql.DB, defaultQuota int64) (int64, error) {
	var total int64
	err := db.QueryRow(
		`SELECT COALESCE(SUM(CASE WHEN storage_quota > 0 THEN storage_quota ELSE ? END), 0) FROM users`,
		defaultQuota,
	).Scan(&total)
	return total, err
}

// --- Server settings ---

func GetSetting(db *sql.DB, key string) (string, error) {
	var val string
	err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&val)
	return val, err
}

func SetSetting(db *sql.DB, key, value string) error {
	_, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
