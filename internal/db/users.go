package db

import (
	"database/sql"
	"errors"
	"fmt"
)

type User struct {
	ID               string
	Username         string
	PasswordHash     string
	AuthSalt         []byte
	KDFSalt          []byte
	EncryptedMK      []byte // master key encrypted with KDF-derived key (AAD=userID)
	RecoveryMK       []byte // master key encrypted with recovery code (AAD=userID)
	PublicKey        []byte // X25519 public key, 32 bytes, stored plaintext
	EncryptedPrivKey []byte // X25519 private key wrapped with master key (AAD=userID)
	RecoveryPrivKey  []byte // X25519 private key wrapped with recovery code (AAD=userID)
	IsAdmin          bool
	StorageQuota     int64 // per-user storage quota in bytes (0 = use server default)
	CreatedAt        string
}

func CreateUser(db *sql.DB, u *User) error {
	isAdmin := 0
	if u.IsAdmin {
		isAdmin = 1
	}
	_, err := db.Exec(
		`INSERT INTO users (
			id, username, password_hash, auth_salt, kdf_salt,
			encrypted_mk, recovery_mk,
			public_key, encrypted_priv_key, recovery_priv_key,
			is_admin, storage_quota, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y', 'now'))`,
		u.ID, u.Username, u.PasswordHash, u.AuthSalt, u.KDFSalt,
		u.EncryptedMK, u.RecoveryMK,
		u.PublicKey, u.EncryptedPrivKey, u.RecoveryPrivKey,
		isAdmin, u.StorageQuota,
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

	if err := tx.Commit(); err != nil {
		return err
	}
	// The account's wrapped keys and every media key are now overwritten in
	// the main file (secure_delete); flush the WAL so its pre-delete page
	// images go too.
	CheckpointWAL(database)
	return nil
}


// ErrKeysChanged is returned when a write was conditioned on the account's
// current public key and the key has since been rotated (password change or
// recovery). The request was authenticated against the old keys; whatever it
// was writing is encrypted to keys the account no longer uses.
var ErrKeysChanged = errors.New("account keys have changed")

// UserKeys is every credential- and key-bearing column of a user row: what a
// password change or recovery replaces in one go.
type UserKeys struct {
	PasswordHash     string
	AuthSalt         []byte
	KDFSalt          []byte
	EncryptedMK      []byte
	RecoveryMK       []byte
	PublicKey        []byte
	EncryptedPrivKey []byte
	RecoveryPrivKey  []byte
}

// ReplaceUserKeysTx swaps in a new password hash, master key wraps and
// keypair, provided the stored public key is still oldPublicKey. The
// compare-and-swap stops two concurrent rotations from both committing: the
// loser prepared its re-seals with a private key that is no longer current.
//
// Returns sql.ErrNoRows if the user no longer exists and ErrKeysChanged if
// another rotation got there first.
func ReplaceUserKeysTx(tx *sql.Tx, userID string, oldPublicKey []byte, k *UserKeys) error {
	res, err := tx.Exec(
		`UPDATE users SET password_hash = ?, auth_salt = ?, kdf_salt = ?,
		        encrypted_mk = ?, recovery_mk = ?,
		        public_key = ?, encrypted_priv_key = ?, recovery_priv_key = ?
		 WHERE id = ? AND public_key = ?`,
		k.PasswordHash, k.AuthSalt, k.KDFSalt,
		k.EncryptedMK, k.RecoveryMK,
		k.PublicKey, k.EncryptedPrivKey, k.RecoveryPrivKey,
		userID, oldPublicKey,
	)
	if err != nil {
		return err
	}
	if err := requireOneRow(res); err != sql.ErrNoRows {
		return err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, userID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return ErrKeysChanged
}

// GetUserPublicKey returns the account's current X25519 public key.
func GetUserPublicKey(db *sql.DB, userID string) ([]byte, error) {
	var pub []byte
	err := db.QueryRow(`SELECT public_key FROM users WHERE id = ?`, userID).Scan(&pub)
	return pub, err
}

// requireOneRow converts an UPDATE that touched zero rows into sql.ErrNoRows
// so handlers inside a tx can abort on "user was deleted underneath us"
// rather than committing a no-op.
func requireOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
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
		`SELECT id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk,
		        public_key, encrypted_priv_key, recovery_priv_key,
		        is_admin, storage_quota, created_at
		 FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.EncryptedMK, &u.RecoveryMK,
		&u.PublicKey, &u.EncryptedPrivKey, &u.RecoveryPrivKey,
		&isAdmin, &u.StorageQuota, &u.CreatedAt)
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
		`SELECT id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk,
		        public_key, encrypted_priv_key, recovery_priv_key,
		        is_admin, storage_quota, created_at
		 FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.EncryptedMK, &u.RecoveryMK,
		&u.PublicKey, &u.EncryptedPrivKey, &u.RecoveryPrivKey,
		&isAdmin, &u.StorageQuota, &u.CreatedAt)
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
