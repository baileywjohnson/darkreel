package db

import (
	"database/sql"
	"time"
)

type MediaItem struct {
	ID          string
	UserID      string
	Name        []byte // encrypted filename
	MediaType   string // "image" or "video"
	MimeType    string
	Size        int64
	ChunkCount  int
	ChunkSize   int
	FileKeyEnc  []byte // file key encrypted with master key
	ThumbKeyEnc []byte // thumbnail key encrypted with master key
	HashNonce   []byte
	Width       *int
	Height      *int
	Duration    *float64
	CreatedAt   time.Time
	UploadedAt  time.Time
}

func InsertMedia(db *sql.DB, m *MediaItem) error {
	_, err := db.Exec(
		`INSERT INTO media (id, user_id, name, media_type, mime_type, size, chunk_count, chunk_size, file_key_enc, thumb_key_enc, hash_nonce, width, height, duration)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.UserID, m.Name, m.MediaType, m.MimeType, m.Size, m.ChunkCount, m.ChunkSize,
		m.FileKeyEnc, m.ThumbKeyEnc, m.HashNonce, m.Width, m.Height, m.Duration,
	)
	return err
}

func ListMedia(db *sql.DB, userID, sortBy, order, mediaType string, limit, offset int) ([]*MediaItem, int, error) {
	allowedSort := map[string]string{
		"date": "created_at",
		"size": "size",
		"name": "name",
		"type": "media_type",
	}
	col, ok := allowedSort[sortBy]
	if !ok {
		col = "created_at"
	}
	if order != "asc" {
		order = "desc"
	}

	where := "WHERE user_id = ?"
	args := []any{userID}
	if mediaType == "image" || mediaType == "video" {
		where += " AND media_type = ?"
		args = append(args, mediaType)
	}

	var total int
	err := db.QueryRow("SELECT COUNT(*) FROM media "+where, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := "SELECT id, user_id, name, media_type, mime_type, size, chunk_count, chunk_size, file_key_enc, thumb_key_enc, hash_nonce, width, height, duration, created_at, uploaded_at FROM media " +
		where + " ORDER BY " + col + " " + order + " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []*MediaItem
	for rows.Next() {
		m := &MediaItem{}
		if err := rows.Scan(&m.ID, &m.UserID, &m.Name, &m.MediaType, &m.MimeType, &m.Size,
			&m.ChunkCount, &m.ChunkSize, &m.FileKeyEnc, &m.ThumbKeyEnc, &m.HashNonce,
			&m.Width, &m.Height, &m.Duration, &m.CreatedAt, &m.UploadedAt); err != nil {
			return nil, 0, err
		}
		items = append(items, m)
	}
	return items, total, rows.Err()
}

func GetMedia(db *sql.DB, id, userID string) (*MediaItem, error) {
	m := &MediaItem{}
	err := db.QueryRow(
		`SELECT id, user_id, name, media_type, mime_type, size, chunk_count, chunk_size, file_key_enc, thumb_key_enc, hash_nonce, width, height, duration, created_at, uploaded_at
		 FROM media WHERE id = ? AND user_id = ?`, id, userID,
	).Scan(&m.ID, &m.UserID, &m.Name, &m.MediaType, &m.MimeType, &m.Size,
		&m.ChunkCount, &m.ChunkSize, &m.FileKeyEnc, &m.ThumbKeyEnc, &m.HashNonce,
		&m.Width, &m.Height, &m.Duration, &m.CreatedAt, &m.UploadedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func DeleteMedia(db *sql.DB, id, userID string) error {
	_, err := db.Exec(`DELETE FROM media WHERE id = ? AND user_id = ?`, id, userID)
	return err
}
