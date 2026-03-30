package db

import (
	"database/sql"
	"time"
)

type MediaItem struct {
	ID            string
	UserID        string
	ChunkCount    int
	FileKeyEnc    []byte // file key encrypted with master key
	ThumbKeyEnc   []byte // thumbnail key encrypted with master key
	HashNonce     []byte
	MetadataEnc   []byte // encrypted metadata blob (name, type, mime, size, dimensions, duration)
	MetadataNonce []byte
	CreatedAt     time.Time
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

func DeleteMedia(db *sql.DB, id, userID string) error {
	_, err := db.Exec(`DELETE FROM media WHERE id = ? AND user_id = ?`, id, userID)
	return err
}
