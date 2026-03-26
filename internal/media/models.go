package media

import "encoding/base64"

// APIMediaItem is the JSON representation of a media item returned to clients.
type APIMediaItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`         // base64-encoded encrypted filename
	MediaType   string   `json:"media_type"`
	MimeType    string   `json:"mime_type"`
	Size        int64    `json:"size"`
	ChunkCount  int      `json:"chunk_count"`
	ChunkSize   int      `json:"chunk_size"`
	FileKeyEnc  string   `json:"file_key_enc"`  // base64
	ThumbKeyEnc string   `json:"thumb_key_enc"` // base64
	HashNonce   string   `json:"hash_nonce"`    // base64
	Width       *int     `json:"width,omitempty"`
	Height      *int     `json:"height,omitempty"`
	Duration    *float64 `json:"duration,omitempty"`
	CreatedAt   string   `json:"created_at"`
	UploadedAt  string   `json:"uploaded_at"`
}

// UploadMeta is the metadata sent by the client when initiating an upload.
type UploadMeta struct {
	Name        string   `json:"name"`         // base64 encrypted filename
	MediaType   string   `json:"media_type"`
	MimeType    string   `json:"mime_type"`
	Size        int64    `json:"size"`
	ChunkCount  int      `json:"chunk_count"`
	FileKeyEnc  string   `json:"file_key_enc"`  // base64
	ThumbKeyEnc string   `json:"thumb_key_enc"` // base64
	HashNonce   string   `json:"hash_nonce"`    // base64
	Width       *int     `json:"width,omitempty"`
	Height      *int     `json:"height,omitempty"`
	Duration    *float64 `json:"duration,omitempty"`
}

func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func FromB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
