package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

func Open(dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "darkreel.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Ensure DB file is owner-readable only (may pre-exist with looser perms).
	// Done after migrate so the file is guaranteed to exist.
	if err := os.Chmod(dbPath, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("chmod database: %w", err)
	}

	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			username      TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			auth_salt     BLOB NOT NULL,
			kdf_salt      BLOB NOT NULL,
			encrypted_mk  BLOB NOT NULL,
			recovery_mk   BLOB,
			is_admin      INTEGER NOT NULL DEFAULT 0,
			created_at    TEXT DEFAULT (strftime('%Y-%W', 'now'))
		);

		CREATE TABLE IF NOT EXISTS user_data (
			user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			folder_tree_enc BLOB,
			folder_tree_nonce BLOB
		);

		CREATE TABLE IF NOT EXISTS media (
			id             TEXT PRIMARY KEY,
			user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			chunk_count    INTEGER NOT NULL,
			file_key_enc   BLOB NOT NULL,
			thumb_key_enc  BLOB NOT NULL,
			hash_nonce     BLOB NOT NULL,
			metadata_enc   BLOB NOT NULL,
			metadata_nonce BLOB NOT NULL,
			created_at     TEXT DEFAULT (strftime('%Y-%W', 'now'))
		);

		CREATE INDEX IF NOT EXISTS idx_media_user ON media(user_id, created_at DESC);
	`)
	return err
}
