package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

// isDuplicateColumnError returns true if the error indicates the column already exists.
func isDuplicateColumnError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

func Open(dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "darkreel.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON&_secure_delete=FAST")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4) // match MaxOpenConns to avoid connection churn

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
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			username      TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			auth_salt     BLOB NOT NULL,
			kdf_salt      BLOB NOT NULL,
			encrypted_mk  BLOB NOT NULL,
			recovery_mk   BLOB,
			is_admin      INTEGER NOT NULL DEFAULT 0,
			created_at    TEXT DEFAULT (strftime('%Y', 'now'))
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
			created_at     TEXT DEFAULT (strftime('%Y', 'now'))
		);

		CREATE INDEX IF NOT EXISTS idx_media_user ON media(user_id, created_at DESC);

		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	// Add storage_quota column to users if it doesn't exist (migration for existing DBs).
	// "duplicate column name" is expected on DBs that already have this column.
	if _, err := tx.Exec(`ALTER TABLE users ADD COLUMN storage_quota INTEGER NOT NULL DEFAULT 0`); err != nil {
		if !isDuplicateColumnError(err) {
			return fmt.Errorf("add storage_quota column: %w", err)
		}
	}

	// Add size_bytes column to media for accurate byte-based quota tracking.
	if _, err := tx.Exec(`ALTER TABLE media ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0`); err != nil {
		if !isDuplicateColumnError(err) {
			return fmt.Errorf("add size_bytes column: %w", err)
		}
	}

	// Covering index for quota queries — must be after size_bytes column exists.
	if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_media_user_size ON media(user_id, size_bytes)`); err != nil {
		return fmt.Errorf("create idx_media_user_size: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// One-time migration: convert chunk-based quotas to byte-based quotas.
	// Detect by checking for a 'quota_unit' setting — absent means still chunk-based.
	// Wrapped in a transaction so a crash mid-migration can't double-multiply quotas.
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = 'quota_unit'`).Scan(new(string)); err != nil {
		mtx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin quota migration: %w", err)
		}
		defer mtx.Rollback()

		// Backfill size_bytes from chunk_count (estimate 1 MB/chunk).
		mtx.Exec(`UPDATE media SET size_bytes = chunk_count * 1048576 WHERE size_bytes = 0 AND chunk_count > 0`)
		// Convert per-user storage_quota from chunks to bytes.
		mtx.Exec(`UPDATE users SET storage_quota = storage_quota * 1048576 WHERE storage_quota > 0`)
		// Convert default_storage_quota setting from chunks to bytes.
		var oldQuota string
		if err := mtx.QueryRow(`SELECT value FROM settings WHERE key = 'default_storage_quota'`).Scan(&oldQuota); err == nil {
			if n, err := strconv.Atoi(oldQuota); err == nil && n > 0 {
				mtx.Exec(`UPDATE settings SET value = ? WHERE key = 'default_storage_quota'`, strconv.Itoa(n*1048576))
			}
		}
		// Mark migration complete.
		mtx.Exec(`INSERT INTO settings (key, value) VALUES ('quota_unit', 'bytes') ON CONFLICT(key) DO UPDATE SET value = excluded.value`)

		if err := mtx.Commit(); err != nil {
			return fmt.Errorf("commit quota migration: %w", err)
		}
	}

	return nil
}
