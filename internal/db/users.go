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
	CreatedAt    time.Time
}

func CreateUser(db *sql.DB, u *User) error {
	_, err := db.Exec(
		`INSERT INTO users (id, username, password_hash, auth_salt, kdf_salt) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.AuthSalt, u.KDFSalt,
	)
	return err
}

func GetUserByUsername(db *sql.DB, username string) (*User, error) {
	u := &User{}
	err := db.QueryRow(
		`SELECT id, username, password_hash, auth_salt, kdf_salt, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func GetUserByID(db *sql.DB, id string) (*User, error) {
	u := &User{}
	err := db.QueryRow(
		`SELECT id, username, password_hash, auth_salt, kdf_salt, created_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.AuthSalt, &u.KDFSalt, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}
