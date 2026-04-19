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

// hashRefreshTokenDomain prefixes the refresh-token hash with a fixed
// domain separator so the hash is not cross-protocol reusable. A DB leak
// cannot be fed into a future feature's "sha256(x)" primitive to produce a
// refresh_token_hash that matches — the attacker would also need to know
// this exact byte sequence and recreate the domain-separated construction.
// Versioned so we can rotate the construction without re-hashing existing
// tokens (just bump the version and force re-authorization).
const hashRefreshTokenDomain = "darkreel:delegation-refresh-v1|"

// HashRefreshToken is the canonical server-side hash used for storage and
// exact-match lookup. Callers feed it the raw user-supplied token.
// We intentionally use SHA-256 with a fixed domain separator (not HMAC with
// the JWT secret): jwtSecret is ephemeral per process by design, and HMACing
// with it would invalidate every stored refresh token on restart, breaking
// the "click and forget" delegation UX. 32-byte random tokens have enough
// entropy that pre-image resistance doesn't need an additional secret.
func HashRefreshToken(raw string) []byte {
	h := sha256.New()
	h.Write([]byte(hashRefreshTokenDomain))
	h.Write([]byte(raw))
	return h.Sum(nil)
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

// ExchangeAuthorizationCode atomically consumes an authorization code and
// creates the backing delegation row in a single transaction.
//
// Atomicity closes two race windows the earlier two-step version had:
//
//   1. Concurrent exchanges on the same code. DELETE ... RETURNING commits
//      a single row-visibility decision under SQLite's locking — the second
//      caller sees zero affected rows and fails out. Without RETURNING, two
//      concurrent SELECTs could both see the row, both delete (one no-op),
//      and both mint a fresh refresh token.
//   2. Code burned on failed insert. With the earlier flow, a failure between
//      the DELETE commit and the InsertDelegation call left the user with a
//      consumed code and no delegation — they had to re-authorize. Now the
//      INSERT runs inside the same tx; any failure rolls the code back.
//
// `now` is passed in so the expiry check uses the same wall clock the caller
// sees elsewhere in the request. `now > expires_at` → ErrCodeExpired.
func ExchangeAuthorizationCode(database *sql.DB, code string, now time.Time, d *Delegation, tokenHash []byte) (*DelegationCode, error) {
	tx, err := database.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// DELETE ... RETURNING: single statement, atomically removes the row and
	// returns its contents. If the code never existed (or a concurrent exchange
	// already consumed it), RETURNING yields no rows — Scan returns ErrNoRows.
	c := &DelegationCode{}
	err = tx.QueryRow(
		`DELETE FROM delegation_codes WHERE code = ?
		 RETURNING code, user_id, client_name, client_url, scope, expires_at`,
		code,
	).Scan(&c.Code, &c.UserID, &c.ClientName, &c.ClientURL, &c.Scope, &c.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if now.Unix() > c.ExpiresAt {
		return nil, ErrCodeExpired
	}

	// Carry the code's metadata into the delegation row so the caller can
	// display a consistent "Connected Apps" entry.
	if d.ClientName == "" {
		d.ClientName = c.ClientName
	}
	if d.ClientURL == "" {
		d.ClientURL = c.ClientURL
	}
	if d.Scope == "" {
		d.Scope = c.Scope
	}
	if d.UserID == "" {
		d.UserID = c.UserID
	}

	if _, err := tx.Exec(
		`INSERT INTO delegations (id, user_id, client_name, client_url, scope, refresh_token_hash, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.ID, d.UserID, d.ClientName, d.ClientURL, d.Scope, tokenHash, d.CreatedAt,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return c, nil
}

// ErrCodeExpired is returned by ExchangeAuthorizationCode when the code was
// present but past its expiry. Callers surface the same "invalid or expired
// code" error to the client either way to avoid state distinguishers.
var ErrCodeExpired = fmt.Errorf("authorization code expired")

// PruneExpiredDelegationCodes deletes expired authorization codes. Called
// periodically from a background goroutine (similar to session cleanup).
func PruneExpiredDelegationCodes(db *sql.DB, now time.Time) error {
	_, err := db.Exec(`DELETE FROM delegation_codes WHERE expires_at < ?`, now.Unix())
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
