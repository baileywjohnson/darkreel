package db

import "database/sql"

type MediaItem struct {
	ID            string
	UserID        string
	ChunkCount    int
	FileKeyEnc    []byte // file key encrypted with master key
	ThumbKeyEnc   []byte // thumbnail key encrypted with master key
	HashNonce     []byte
	MetadataEnc   []byte // encrypted metadata blob (name, type, mime, size, dimensions, duration)
	MetadataNonce []byte
	CreatedAt     string // coarse timestamp (year-week) to limit metadata leakage
}

func InsertMedia(db *sql.DB, m *MediaItem) error {
	_, err := db.Exec(
		`INSERT INTO media (id, user_id, chunk_count, file_key_enc, thumb_key_enc, hash_nonce, metadata_enc, metadata_nonce)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.UserID, m.ChunkCount, m.FileKeyEnc, m.ThumbKeyEnc, m.HashNonce, m.MetadataEnc, m.MetadataNonce,
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

	query := "SELECT id, user_id, chunk_count, file_key_enc, thumb_key_enc, hash_nonce, metadata_enc, metadata_nonce, created_at FROM media " +
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
		if err := rows.Scan(&m.ID, &m.UserID, &m.ChunkCount, &m.FileKeyEnc, &m.ThumbKeyEnc,
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
		`SELECT id, user_id, chunk_count, file_key_enc, thumb_key_enc, hash_nonce, metadata_enc, metadata_nonce, created_at
		 FROM media WHERE id = ? AND user_id = ?`, id, userID,
	).Scan(&m.ID, &m.UserID, &m.ChunkCount, &m.FileKeyEnc, &m.ThumbKeyEnc,
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

func DeleteMedia(db *sql.DB, id, userID string) error {
	_, err := db.Exec(`DELETE FROM media WHERE id = ? AND user_id = ?`, id, userID)
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
