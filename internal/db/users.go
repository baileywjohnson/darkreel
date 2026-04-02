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
	RecoveryMK   []byte // master key encrypted with recovery code
	CreatedAt    time.Time
}

func CreateUser(db *sql.DB, u *User) error {
	_, err := db.Exec(
		`INSERT INTO users (id, username, password_hash, auth_salt, kdf_salt, recovery_mk) VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.AuthSalt, u.KDFSalt, u.RecoveryMK,
	)
	return err
}

func UpdateUserRecoveryMK(db *sql.DB, userID string, recoveryMK []byte) error {
	_, err := db.Exec(`UPDATE users SET recovery_mk = ? WHERE id = ?`, recoveryMK, userID)
	return err
}

func UpdateUserPassword(db *sql.DB, userID, passwordHash string, authSalt, kdfSalt []byte) error {
	_, err := db.Exec(
		`UPDATE users SET password_hash = ?, auth_salt = ?, kdf_salt = ? WHERE id = ?`,
		passwordHash, authSalt, kdfSalt, userID,
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
	err := db.QueryRow(
		`SELECT id, username, password_hash, auth_salt, kdf_salt, recovery_mk, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.RecoveryMK, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func GetUserByID(db *sql.DB, id string) (*User, error) {
	u := &User{}
	err := db.QueryRow(
		`SELECT id, username, password_hash, auth_salt, kdf_salt, recovery_mk, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.RecoveryMK, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}
