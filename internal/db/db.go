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
			created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS media (
			id             TEXT PRIMARY KEY,
			user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name           BLOB NOT NULL,
			media_type     TEXT NOT NULL,
			mime_type      TEXT NOT NULL,
			size           INTEGER NOT NULL,
			chunk_count    INTEGER NOT NULL,
			chunk_size     INTEGER NOT NULL DEFAULT 1048576,
			file_key_enc   BLOB NOT NULL,
			thumb_key_enc  BLOB NOT NULL,
			hash_nonce     BLOB NOT NULL,
			width          INTEGER,
			height         INTEGER,
			duration       REAL,
			created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
			uploaded_at    DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_media_user ON media(user_id, created_at DESC);
	`)
	return err
}
