package db

import (
	"bytes"
	"database/sql"
	"errors"
	"strconv"
)

type MediaItem struct {
	ID                string
	UserID            string
	ChunkCount        int
	SizeBytes         int64  // on-disk size in bytes, padding included (what quota is charged on)
	FileKeySealed     []byte // file key sealed with user's public key (92-byte sealed box)
	ThumbKeySealed    []byte // thumbnail key sealed with user's public key (92-byte sealed box)
	MetadataKeySealed []byte // metadata key sealed with user's public key (92-byte sealed box)
	HashNonce         []byte
	MetadataEnc       []byte // metadata (name, type, mime, dims, duration) encrypted with metadata key
	MetadataNonce     []byte
	CreatedAt         string // coarse timestamp (year-only) to limit metadata leakage
}

func InsertMedia(db *sql.DB, m *MediaItem) error {
	_, err := db.Exec(
		`INSERT INTO media (id, user_id, chunk_count, size_bytes,
		                    file_key_sealed, thumb_key_sealed, metadata_key_sealed,
		                    hash_nonce, metadata_enc, metadata_nonce, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y', 'now'))`,
		m.ID, m.UserID, m.ChunkCount, m.SizeBytes,
		m.FileKeySealed, m.ThumbKeySealed, m.MetadataKeySealed,
		m.HashNonce, m.MetadataEnc, m.MetadataNonce,
	)
	return err
}

// InsertMediaForKey inserts m only while the owner's public key is still
// publicKey — the key the uploading client sealed m's keys to. Returns
// ErrKeysChanged if the account's keypair was rotated in the meantime: the
// sealed keys would be unopenable, so the row must not land.
func InsertMediaForKey(db *sql.DB, m *MediaItem, publicKey []byte) error {
	res, err := db.Exec(
		`INSERT INTO media (id, user_id, chunk_count, size_bytes,
		                    file_key_sealed, thumb_key_sealed, metadata_key_sealed,
		                    hash_nonce, metadata_enc, metadata_nonce, created_at)
		 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y', 'now')
		 WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND public_key = ?)`,
		m.ID, m.UserID, m.ChunkCount, m.SizeBytes,
		m.FileKeySealed, m.ThumbKeySealed, m.MetadataKeySealed,
		m.HashNonce, m.MetadataEnc, m.MetadataNonce,
		m.UserID, publicKey,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrKeysChanged
	}
	return nil
}

// MediaKeys is the part of a media row that a keypair rotation rewrites: the
// three sealed keys, plus the encrypted metadata (which carries an ownership
// tag computed over the sealed keys).
type MediaKeys struct {
	ID                string
	FileKeySealed     []byte
	ThumbKeySealed    []byte
	MetadataKeySealed []byte
	MetadataEnc       []byte
	MetadataNonce     []byte
}

// Equal reports whether a and b hold identical bytes.
func (a *MediaKeys) Equal(b *MediaKeys) bool {
	return a.ID == b.ID &&
		bytes.Equal(a.FileKeySealed, b.FileKeySealed) &&
		bytes.Equal(a.ThumbKeySealed, b.ThumbKeySealed) &&
		bytes.Equal(a.MetadataKeySealed, b.MetadataKeySealed) &&
		bytes.Equal(a.MetadataEnc, b.MetadataEnc) &&
		bytes.Equal(a.MetadataNonce, b.MetadataNonce)
}

// Querier is satisfied by both *sql.DB and *sql.Tx.
type Querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// ListMediaKeys returns the sealed keys and encrypted metadata of every media
// row belonging to userID.
func ListMediaKeys(q Querier, userID string) ([]*MediaKeys, error) {
	rows, err := q.Query(
		`SELECT id, file_key_sealed, thumb_key_sealed, metadata_key_sealed,
		        metadata_enc, metadata_nonce
		 FROM media WHERE user_id = ?`, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*MediaKeys
	for rows.Next() {
		k := &MediaKeys{}
		if err := rows.Scan(&k.ID, &k.FileKeySealed, &k.ThumbKeySealed, &k.MetadataKeySealed,
			&k.MetadataEnc, &k.MetadataNonce); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UpdateMediaKeysTx rewrites a row's sealed keys and encrypted metadata.
func UpdateMediaKeysTx(tx *sql.Tx, userID string, k *MediaKeys) error {
	res, err := tx.Exec(
		`UPDATE media SET file_key_sealed = ?, thumb_key_sealed = ?, metadata_key_sealed = ?,
		                  metadata_enc = ?, metadata_nonce = ?
		 WHERE id = ? AND user_id = ?`,
		k.FileKeySealed, k.ThumbKeySealed, k.MetadataKeySealed,
		k.MetadataEnc, k.MetadataNonce, k.ID, userID,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

func ListMedia(db *sql.DB, userID string, limit, offset int) ([]*MediaItem, int, error) {
	query := `SELECT id, user_id, chunk_count, size_bytes,
	                 file_key_sealed, thumb_key_sealed, metadata_key_sealed,
	                 hash_nonce, metadata_enc, metadata_nonce, created_at,
	                 COUNT(*) OVER() AS total
	          FROM media WHERE user_id = ?
	          ORDER BY created_at DESC LIMIT ? OFFSET ?`

	rows, err := db.Query(query, userID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []*MediaItem
	var total int
	for rows.Next() {
		m := &MediaItem{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.ChunkCount, &m.SizeBytes,
			&m.FileKeySealed, &m.ThumbKeySealed, &m.MetadataKeySealed,
			&m.HashNonce, &m.MetadataEnc, &m.MetadataNonce, &m.CreatedAt, &total); err != nil {
			return nil, 0, err
		}
		items = append(items, m)
	}
	return items, total, rows.Err()
}

func GetMedia(db *sql.DB, id, userID string) (*MediaItem, error) {
	m := &MediaItem{}
	err := db.QueryRow(
		`SELECT id, user_id, chunk_count, size_bytes,
		        file_key_sealed, thumb_key_sealed, metadata_key_sealed,
		        hash_nonce, metadata_enc, metadata_nonce, created_at
		 FROM media WHERE id = ? AND user_id = ?`, id, userID,
	).Scan(&m.ID, &m.UserID, &m.ChunkCount, &m.SizeBytes,
		&m.FileKeySealed, &m.ThumbKeySealed, &m.MetadataKeySealed,
		&m.HashNonce, &m.MetadataEnc, &m.MetadataNonce, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func ListMediaIDsByUser(db *sql.DB, userID string) ([]string, error) {
	rows, err := db.Query(`SELECT id FROM media WHERE user_id = ?`, userID)
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

// MediaSummary is a lightweight struct for startup integrity checks.
type MediaSummary struct {
	ID         string
	UserID     string
	ChunkCount int
}

// ListAllMediaSummaries returns (id, user_id, chunk_count) for all media items.
func ListAllMediaSummaries(db *sql.DB) ([]MediaSummary, error) {
	rows, err := db.Query(`SELECT id, user_id, chunk_count FROM media`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []MediaSummary
	for rows.Next() {
		var s MediaSummary
		if err := rows.Scan(&s.ID, &s.UserID, &s.ChunkCount); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, rows.Err()
}

func GetUserChunkCount(db *sql.DB, userID string) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COALESCE(SUM(chunk_count), 0) FROM media WHERE user_id = ?`, userID).Scan(&count)
	return count, err
}

// GetUserStorageBytes returns the total stored bytes for a user.
func GetUserStorageBytes(db *sql.DB, userID string) (int64, error) {
	var total int64
	err := db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM media WHERE user_id = ?`, userID).Scan(&total)
	return total, err
}

// QuotaInfo holds the result of a combined quota pre-check query.
type QuotaInfo struct {
	UserQuota    int64 // per-user override (0 = use default)
	DefaultQuota int64 // server default from settings (0 = not set)
	UsedBytes    int64 // current total bytes for the user
}

// GetQuotaInfo fetches user quota override, server default quota, and current
// usage in a single query to avoid multiple round trips during upload pre-check.
func GetQuotaInfo(database *sql.DB, userID string) (*QuotaInfo, error) {
	qi := &QuotaInfo{}
	var defaultStr sql.NullString
	err := database.QueryRow(`
		SELECT u.storage_quota,
		       (SELECT value FROM settings WHERE key = 'default_storage_quota'),
		       COALESCE((SELECT SUM(m.size_bytes) FROM media m WHERE m.user_id = ?), 0)
		FROM users u WHERE u.id = ?`,
		userID, userID,
	).Scan(&qi.UserQuota, &defaultStr, &qi.UsedBytes)
	if err != nil {
		return nil, err
	}
	if defaultStr.Valid {
		qi.DefaultQuota, _ = strconv.ParseInt(defaultStr.String, 10, 64)
	}
	return qi, nil
}

// EffectiveQuota resolves a user's storage quota in bytes. Priority: per-user
// DB override > server default in DB > fallback (the MAX_STORAGE_GB env var).
// Returns <= 0 when no quota is configured.
func EffectiveQuota(qi *QuotaInfo, fallback int64) int64 {
	quota := fallback
	if qi.DefaultQuota > 0 {
		quota = qi.DefaultQuota
	}
	if qi.UserQuota > 0 {
		quota = qi.UserQuota
	}
	return quota
}

// UpdateMediaSizeIfSet overwrites size_bytes only for completed uploads
// (size_bytes > 0), leaving in-progress rows alone.
func UpdateMediaSizeIfSet(db *sql.DB, id string, sizeBytes int64) error {
	_, err := db.Exec(`UPDATE media SET size_bytes = ? WHERE id = ? AND size_bytes > 0`, sizeBytes, id)
	return err
}

// ErrMediaGone is returned by UpdateMediaSizeWithQuotaCheck when the media
// row no longer exists.
var ErrMediaGone = errors.New("media record no longer exists")

// UpdateMediaSizeWithQuotaCheck atomically verifies that adding sizeBytes
// for userID would not exceed quota, then updates the media record.
// Returns (true, nil) on success, (false, nil) if quota would be exceeded.
func UpdateMediaSizeWithQuotaCheck(database *sql.DB, id, userID string, sizeBytes, quota int64) (bool, error) {
	tx, err := database.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var currentBytes int64
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM media WHERE user_id = ?`, userID).Scan(&currentBytes); err != nil {
		return false, err
	}
	if currentBytes+sizeBytes > quota {
		return false, nil
	}
	res, err := tx.Exec(`UPDATE media SET size_bytes = ? WHERE id = ? AND user_id = ?`, sizeBytes, id, userID)
	if err != nil {
		return false, err
	}
	// The row can vanish mid-upload (the user deleted it, or the account was
	// deleted and cascaded). Reporting success then would tell the client an
	// upload landed that no longer exists.
	if n, err := res.RowsAffected(); err != nil {
		return false, err
	} else if n != 1 {
		return false, ErrMediaGone
	}
	return true, tx.Commit()
}

// ListMediaWithZeroSize returns media records that have size_bytes=0 but chunk_count>0.
// These are uploads where the server crashed after writing chunks but before updating size.
func ListMediaWithZeroSize(db *sql.DB) ([]MediaSummary, error) {
	rows, err := db.Query(`SELECT id, user_id, chunk_count FROM media WHERE size_bytes = 0 AND chunk_count > 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []MediaSummary
	for rows.Next() {
		var s MediaSummary
		if err := rows.Scan(&s.ID, &s.UserID, &s.ChunkCount); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, rows.Err()
}

func DeleteMedia(db *sql.DB, id, userID string) error {
	_, err := db.Exec(`DELETE FROM media WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// DeleteMediaByID deletes a media record by ID only (used during startup cleanup).
func DeleteMediaByID(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM media WHERE id = ?`, id)
	return err
}

// UpdateMediaMetadata replaces an item's encrypted metadata, provided the
// owner's public key is still publicKey (see InsertMediaForKey). Returns
// sql.ErrNoRows if the item doesn't exist and ErrKeysChanged if the keypair
// was rotated since the request was authenticated.
func UpdateMediaMetadata(db *sql.DB, id, userID string, metadataEnc, metadataNonce, publicKey []byte) error {
	result, err := db.Exec(
		`UPDATE media SET metadata_enc = ?, metadata_nonce = ? WHERE id = ? AND user_id = ?
		 AND EXISTS (SELECT 1 FROM users WHERE id = ? AND public_key = ?)`,
		metadataEnc, metadataNonce, id, userID, userID, publicKey,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		if cur, err := GetUserPublicKey(db, userID); err == nil && !bytes.Equal(cur, publicKey) {
			return ErrKeysChanged
		}
		return sql.ErrNoRows
	}
	return nil
}

// --- Folder tree (encrypted per-user blob) ---

type UserData struct {
	FolderTreeEnc   []byte
	FolderTreeNonce []byte
}

func GetUserData(db *sql.DB, userID string) (*UserData, error) {
	d := &UserData{}
	err := db.QueryRow(
		`SELECT folder_tree_enc, folder_tree_nonce FROM user_data WHERE user_id = ?`, userID,
	).Scan(&d.FolderTreeEnc, &d.FolderTreeNonce)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// SaveUserData stores the folder tree blob, provided the user's public key
// is still publicKey. The blob is encrypted under the master key, which is
// rotated together with the keypair; a save authenticated before a rotation
// but landing after it would replace the tree with one nobody can decrypt.
// Returns ErrKeysChanged in that case.
func SaveUserData(db *sql.DB, userID string, folderTreeEnc, folderTreeNonce, publicKey []byte) error {
	res, err := db.Exec(`
		INSERT INTO user_data (user_id, folder_tree_enc, folder_tree_nonce)
		SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND public_key = ?)
		ON CONFLICT(user_id) DO UPDATE SET folder_tree_enc = excluded.folder_tree_enc, folder_tree_nonce = excluded.folder_tree_nonce
	`, userID, folderTreeEnc, folderTreeNonce, userID, publicKey)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrKeysChanged
	}
	return nil
}

// GetUserDataTx is GetUserData inside a transaction.
func GetUserDataTx(tx *sql.Tx, userID string) (*UserData, error) {
	d := &UserData{}
	err := tx.QueryRow(
		`SELECT folder_tree_enc, folder_tree_nonce FROM user_data WHERE user_id = ?`, userID,
	).Scan(&d.FolderTreeEnc, &d.FolderTreeNonce)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// UpdateUserDataTx overwrites an existing folder tree blob.
func UpdateUserDataTx(tx *sql.Tx, userID string, folderTreeEnc, folderTreeNonce []byte) error {
	res, err := tx.Exec(
		`UPDATE user_data SET folder_tree_enc = ?, folder_tree_nonce = ? WHERE user_id = ?`,
		folderTreeEnc, folderTreeNonce, userID,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}
