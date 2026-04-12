package db

import (
	"database/sql"
	"strconv"
)

type MediaItem struct {
	ID            string
	UserID        string
	ChunkCount    int
	SizeBytes     int    // total raw upload size in bytes (for quota tracking)
	FileKeyEnc    []byte // file key encrypted with master key
	ThumbKeyEnc   []byte // thumbnail key encrypted with master key
	HashNonce     []byte
	MetadataEnc   []byte // encrypted metadata blob (name, type, mime, size, dimensions, duration)
	MetadataNonce []byte
	CreatedAt     string // coarse timestamp (year-only) to limit metadata leakage
}

func InsertMedia(db *sql.DB, m *MediaItem) error {
	_, err := db.Exec(
		`INSERT INTO media (id, user_id, chunk_count, size_bytes, file_key_enc, thumb_key_enc, hash_nonce, metadata_enc, metadata_nonce, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y', 'now'))`,
		m.ID, m.UserID, m.ChunkCount, m.SizeBytes, m.FileKeyEnc, m.ThumbKeyEnc, m.HashNonce, m.MetadataEnc, m.MetadataNonce,
	)
	return err
}

func ListMedia(db *sql.DB, userID string, limit, offset int) ([]*MediaItem, int, error) {
	where := "WHERE user_id = ?"
	args := []any{userID}

	var total int
	err := db.QueryRow("SELECT COUNT(*) FROM media "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := "SELECT id, user_id, chunk_count, size_bytes, file_key_enc, thumb_key_enc, hash_nonce, metadata_enc, metadata_nonce, created_at FROM media " +
		where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []*MediaItem
	for rows.Next() {
		m := &MediaItem{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.ChunkCount, &m.SizeBytes, &m.FileKeyEnc, &m.ThumbKeyEnc,
			&m.HashNonce, &m.MetadataEnc, &m.MetadataNonce, &m.CreatedAt); err != nil {
			return nil, 0, err
		}
		items = append(items, m)
	}
	return items, total, rows.Err()
}

func GetMedia(db *sql.DB, id, userID string) (*MediaItem, error) {
	m := &MediaItem{}
	err := db.QueryRow(
		`SELECT id, user_id, chunk_count, size_bytes, file_key_enc, thumb_key_enc, hash_nonce, metadata_enc, metadata_nonce, created_at
		 FROM media WHERE id = ? AND user_id = ?`, id, userID,
	).Scan(&m.ID, &m.UserID, &m.ChunkCount, &m.SizeBytes, &m.FileKeyEnc, &m.ThumbKeyEnc,
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
func GetUserStorageBytes(db *sql.DB, userID string) (int, error) {
	var total int
	err := db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM media WHERE user_id = ?`, userID).Scan(&total)
	return total, err
}

// QuotaInfo holds the result of a combined quota pre-check query.
type QuotaInfo struct {
	UserQuota    int // per-user override (0 = use default)
	DefaultQuota int // server default from settings (0 = not set)
	UsedBytes    int // current total bytes for the user
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
		qi.DefaultQuota, _ = strconv.Atoi(defaultStr.String)
	}
	return qi, nil
}

// UpdateMediaSize sets the actual byte size after upload completes.
func UpdateMediaSize(db *sql.DB, id string, sizeBytes int) error {
	_, err := db.Exec(`UPDATE media SET size_bytes = ? WHERE id = ?`, sizeBytes, id)
	return err
}

// UpdateMediaSizeWithQuotaCheck atomically verifies that adding sizeBytes
// for userID would not exceed quota, then updates the media record.
// Returns (true, nil) on success, (false, nil) if quota would be exceeded.
func UpdateMediaSizeWithQuotaCheck(database *sql.DB, id, userID string, sizeBytes, quota int) (bool, error) {
	tx, err := database.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var currentBytes int
	if err := tx.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM media WHERE user_id = ?`, userID).Scan(&currentBytes); err != nil {
		return false, err
	}
	if currentBytes+sizeBytes > quota {
		return false, nil
	}
	if _, err := tx.Exec(`UPDATE media SET size_bytes = ? WHERE id = ? AND user_id = ?`, sizeBytes, id, userID); err != nil {
		return false, err
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

func UpdateMediaMetadata(db *sql.DB, id, userID string, metadataEnc, metadataNonce []byte) error {
	result, err := db.Exec(
		`UPDATE media SET metadata_enc = ?, metadata_nonce = ? WHERE id = ? AND user_id = ?`,
		metadataEnc, metadataNonce, id, userID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
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

func SaveUserData(db *sql.DB, userID string, folderTreeEnc, folderTreeNonce []byte) error {
	_, err := db.Exec(`
		INSERT INTO user_data (user_id, folder_tree_enc, folder_tree_nonce)
		VALUES (?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET folder_tree_enc = excluded.folder_tree_enc, folder_tree_nonce = excluded.folder_tree_nonce
	`, userID, folderTreeEnc, folderTreeNonce)
	return err
}
