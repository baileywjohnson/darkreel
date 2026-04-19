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
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON&_secure_delete=FAST")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8) // match MaxOpenConns to avoid connection churn

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

// schemaVersion is the on-disk schema version. Bumped to 2 for Shape 2 of the
// credential-chain redesign: per-user X25519 keypairs, sealed-box file keys,
// delegation tables. Any v1 database is refused at boot — the operator must
// wipe data/darkreel.db before upgrading (clean-break migration; no in-place
// path exists because generating keypairs for existing users would require
// their master keys, which the server never holds at rest).
const schemaVersion = "2"

func migrate(db *sql.DB) error {
	// Reject v1 databases at boot. An old install has the users table but no
	// schema_version setting (we introduced the setting in v2). A fresh install
	// has neither, and falls through to the v2 CREATE TABLE below.
	usersExists, err := tableExists(db, "users")
	if err != nil {
		return fmt.Errorf("probe schema: %w", err)
	}
	if usersExists {
		// Propagate unexpected Scan errors so a corrupted or manipulated DB
		// fails boot rather than silently treating a read failure as a
		// version mismatch that might get "fixed" by a later ALTER path.
		var ver string
		err := db.QueryRow(`SELECT value FROM settings WHERE key = 'schema_version'`).Scan(&ver)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("read schema version: %w", err)
		}
		if ver != schemaVersion {
			return fmt.Errorf(
				"refusing to start: on-disk schema version is %q, expected %q. "+
					"Shape 2 introduces asymmetric upload keys and is not in-place migratable. "+
					"Stop the service, back up or delete data/darkreel.db, and start again. "+
					"A fresh admin will be re-bootstrapped from DARKREEL_ADMIN_PASSWORD on next boot",
				ver, schemaVersion,
			)
		}
		// Belt-and-braces: even if schema_version is stamped correctly, refuse
		// to boot unless the users table actually has the v2 keypair columns.
		// Prevents a server from serving empty public_keys (which, if sealed
		// to, effectively leaks everything) under adverse migration paths or
		// manual DB tampering.
		for _, col := range []string{"public_key", "encrypted_priv_key", "recovery_priv_key"} {
			exists, err := columnExists(db, "users", col)
			if err != nil {
				return fmt.Errorf("probe users.%s: %w", col, err)
			}
			if !exists {
				return fmt.Errorf(
					"refusing to start: schema_version is %q but users.%s column is missing. "+
						"This indicates a manual or incomplete migration. Back up and wipe data/darkreel.db",
					ver, col,
				)
			}
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id                  TEXT PRIMARY KEY,
			username            TEXT UNIQUE NOT NULL,
			password_hash       TEXT NOT NULL,
			auth_salt           BLOB NOT NULL,
			kdf_salt            BLOB NOT NULL,
			encrypted_mk        BLOB NOT NULL,
			recovery_mk         BLOB,
			public_key          BLOB NOT NULL,
			encrypted_priv_key  BLOB NOT NULL,
			recovery_priv_key   BLOB NOT NULL,
			is_admin            INTEGER NOT NULL DEFAULT 0,
			storage_quota       INTEGER NOT NULL DEFAULT 0,
			created_at          TEXT DEFAULT (strftime('%Y', 'now'))
		);

		CREATE TABLE IF NOT EXISTS user_data (
			user_id           TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			folder_tree_enc   BLOB,
			folder_tree_nonce BLOB
		);

		CREATE TABLE IF NOT EXISTS media (
			id                  TEXT PRIMARY KEY,
			user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			chunk_count         INTEGER NOT NULL,
			size_bytes          INTEGER NOT NULL DEFAULT 0,
			file_key_sealed     BLOB NOT NULL,
			thumb_key_sealed    BLOB NOT NULL,
			metadata_key_sealed BLOB NOT NULL,
			hash_nonce          BLOB NOT NULL,
			metadata_enc        BLOB NOT NULL,
			metadata_nonce      BLOB NOT NULL,
			created_at          TEXT DEFAULT (strftime('%Y', 'now'))
		);

		CREATE INDEX IF NOT EXISTS idx_media_user      ON media(user_id, created_at DESC);
		CREATE INDEX IF NOT EXISTS idx_media_user_size ON media(user_id, size_bytes);

		CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS delegations (
			id                  TEXT PRIMARY KEY,
			user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			client_name         TEXT NOT NULL,
			client_url          TEXT NOT NULL,
			scope               TEXT NOT NULL,
			refresh_token_hash  BLOB NOT NULL UNIQUE,
			created_at          TEXT NOT NULL,
			last_used_at        TEXT
		);

		CREATE INDEX IF NOT EXISTS idx_delegations_user ON delegations(user_id);

		CREATE TABLE IF NOT EXISTS delegation_codes (
			code         TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			client_name  TEXT NOT NULL,
			client_url   TEXT NOT NULL,
			scope        TEXT NOT NULL,
			expires_at   INTEGER NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_delegation_codes_expires ON delegation_codes(expires_at);
	`)
	if err != nil {
		return err
	}

	// Stamp the schema version so future migrations (and the v1 guard above)
	// have an authoritative marker.
	if _, err := tx.Exec(
		`INSERT INTO settings (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		schemaVersion,
	); err != nil {
		return fmt.Errorf("stamp schema version: %w", err)
	}

	// quota_unit marker is still written so the old chunk-to-bytes migration
	// skips on fresh v2 installs.
	if _, err := tx.Exec(
		`INSERT INTO settings (key, value) VALUES ('quota_unit', 'bytes') ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
	); err != nil {
		return fmt.Errorf("stamp quota_unit: %w", err)
	}

	return tx.Commit()
}

// tableExists returns true iff a SQLite table with the given name is present.
func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// columnExists returns true iff the named table has a column of the given name.
// Used to verify the v2 keypair columns are actually present before trusting
// the schema_version setting on boot.
func columnExists(db *sql.DB, table, column string) (bool, error) {
	// PRAGMA doesn't accept parameterized table names, but table is a
	// hard-coded literal at every call site (never user-controlled).
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, rows.Err()
		}
	}
	return false, rows.Err()
}
