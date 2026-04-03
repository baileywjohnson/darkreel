package db

import (
	"database/sql"
	"time"
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
	CreatedAt    time.Time
}

func CreateUser(db *sql.DB, u *User) error {
	isAdmin := 0
	if u.IsAdmin {
		isAdmin = 1
	}
	_, err := db.Exec(
		`INSERT INTO users (id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.AuthSalt, u.KDFSalt, u.EncryptedMK, u.RecoveryMK, isAdmin,
	)
	return err
}

func ListUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query(`SELECT id, username, is_admin, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var isAdmin int
		if err := rows.Scan(&u.ID, &u.Username, &isAdmin, &u.CreatedAt); err != nil {
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

func UpdateUserRecoveryMK(db *sql.DB, userID string, recoveryMK []byte) error {
	_, err := db.Exec(`UPDATE users SET recovery_mk = ? WHERE id = ?`, recoveryMK, userID)
	return err
}

func UpdateUserAuth(db *sql.DB, userID, passwordHash string, authSalt, kdfSalt, encryptedMK []byte) error {
	_, err := db.Exec(
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
		`SELECT id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk, is_admin, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.EncryptedMK, &u.RecoveryMK, &isAdmin, &u.CreatedAt)
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
		`SELECT id, username, password_hash, auth_salt, kdf_salt, encrypted_mk, recovery_mk, is_admin, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.EncryptedMK, &u.RecoveryMK, &isAdmin, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.IsAdmin = isAdmin != 0
	return u, nil
}
