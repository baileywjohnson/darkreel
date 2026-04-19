package db

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

// Delegation represents an authorized delegated upload client for a user.
// Scope is "upload" in v1; the column is reserved for later expansion.
// The plaintext refresh token is returned to the client exactly once (at
// exchange time) and never stored — only sha256 of it is held server-side so
// a database leak cannot be replayed against the delegation endpoints.
type Delegation struct {
	ID          string
	UserID      string
	ClientName  string
	ClientURL   string
	Scope       string
	CreatedAt   string
	LastUsedAt  sql.NullString
}

// DelegationCode is a short-lived one-use authorization code. Bound to a
// specific user + intended client; consumed atomically on exchange.
type DelegationCode struct {
	Code       string
	UserID     string
	ClientName string
	ClientURL  string
	Scope      string
	ExpiresAt  int64
}

// HashRefreshToken is the canonical server-side hash used for storage and
// constant-time lookup. Callers are responsible for feeding it the raw,
// user-supplied token (not any prefix, not trimmed).
func HashRefreshToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

// InsertDelegationCode stores a one-use authorization code with a TTL.
func InsertDelegationCode(db *sql.DB, c *DelegationCode) error {
	_, err := db.Exec(
		`INSERT INTO delegation_codes (code, user_id, client_name, client_url, scope, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.Code, c.UserID, c.ClientName, c.ClientURL, c.Scope, c.ExpiresAt,
	)
	return err
}

// ConsumeDelegationCode atomically reads and deletes a code, returning the row
// if it existed and hadn't yet expired. A transaction + DELETE ensures a code
// can be exchanged at most once, even under concurrent requests.
func ConsumeDelegationCode(database *sql.DB, code string, now time.Time) (*DelegationCode, error) {
	tx, err := database.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	c := &DelegationCode{}
	err = tx.QueryRow(
		`SELECT code, user_id, client_name, client_url, scope, expires_at
		 FROM delegation_codes WHERE code = ?`, code,
	).Scan(&c.Code, &c.UserID, &c.ClientName, &c.ClientURL, &c.Scope, &c.ExpiresAt)
	if err != nil {
		return nil, err
	}
	// DELETE regardless of expiry so an expired code cannot be retried later.
	if _, err := tx.Exec(`DELETE FROM delegation_codes WHERE code = ?`, code); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if now.Unix() > c.ExpiresAt {
		return nil, fmt.Errorf("authorization code expired")
	}
	return c, nil
}

// PruneExpiredDelegationCodes deletes expired authorization codes. Called
// periodically from a background goroutine (similar to session cleanup).
func PruneExpiredDelegationCodes(db *sql.DB, now time.Time) error {
	_, err := db.Exec(`DELETE FROM delegation_codes WHERE expires_at < ?`, now.Unix())
	return err
}

// InsertDelegation records a new active delegation. tokenHash must be
// sha256(raw_refresh_token).
func InsertDelegation(db *sql.DB, d *Delegation, tokenHash []byte) error {
	_, err := db.Exec(
		`INSERT INTO delegations (id, user_id, client_name, client_url, scope, refresh_token_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserID, d.ClientName, d.ClientURL, d.Scope, tokenHash, d.CreatedAt,
	)
	return err
}

// GetDelegationByTokenHash looks up the active delegation by its refresh-token
// hash. Returns sql.ErrNoRows if no such delegation exists.
func GetDelegationByTokenHash(db *sql.DB, tokenHash []byte) (*Delegation, error) {
	d := &Delegation{}
	err := db.QueryRow(
		`SELECT id, user_id, client_name, client_url, scope, created_at, last_used_at
		 FROM delegations WHERE refresh_token_hash = ?`, tokenHash,
	).Scan(&d.ID, &d.UserID, &d.ClientName, &d.ClientURL, &d.Scope, &d.CreatedAt, &d.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// TouchDelegation updates last_used_at for observability in the user's
// "Connected Apps" UI.
func TouchDelegation(db *sql.DB, id string, now time.Time) error {
	_, err := db.Exec(
		`UPDATE delegations SET last_used_at = ? WHERE id = ?`,
		now.UTC().Format(time.RFC3339), id,
	)
	return err
}

// ListDelegations returns active delegations for a user, ordered by creation.
func ListDelegations(db *sql.DB, userID string) ([]*Delegation, error) {
	rows, err := db.Query(
		`SELECT id, user_id, client_name, client_url, scope, created_at, last_used_at
		 FROM delegations WHERE user_id = ? ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Delegation
	for rows.Next() {
		d := &Delegation{}
		if err := rows.Scan(&d.ID, &d.UserID, &d.ClientName, &d.ClientURL, &d.Scope, &d.CreatedAt, &d.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteDelegation removes a single delegation (user-initiated revoke).
func DeleteDelegation(db *sql.DB, userID, id string) error {
	res, err := db.Exec(
		`DELETE FROM delegations WHERE id = ? AND user_id = ?`, id, userID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteAllDelegationsForUser removes every active delegation for a user.
// Called on password change so a credential reset implicitly revokes all
// delegated clients (matches the stated threat model: password change =
// assume-compromise-and-reset-everything).
func DeleteAllDelegationsForUser(database *sql.DB, userID string) error {
	_, err := database.Exec(`DELETE FROM delegations WHERE user_id = ?`, userID)
	return err
}

// DeleteAllDelegationsForUserTx is the transactional variant, used when the
// caller is already inside a password-change transaction.
func DeleteAllDelegationsForUserTx(tx *sql.Tx, userID string) error {
	_, err := tx.Exec(`DELETE FROM delegations WHERE user_id = ?`, userID)
	return err
}
