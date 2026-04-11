package media

import "encoding/base64"

// APIMediaItem is the JSON representation of a media item returned to clients.
// Metadata (name, type, mime, size, dimensions, duration) is encrypted — the server
// stores it as an opaque blob and returns it for the client to decrypt.
// APIMediaItem is the JSON representation of a media item returned to clients.
// chunk_count is deliberately omitted — the client reads it from the encrypted
// metadata to avoid leaking approximate file size to network observers.
type APIMediaItem struct {
	ID            string `json:"id"`
	FileKeyEnc    string `json:"file_key_enc"`    // base64
	ThumbKeyEnc   string `json:"thumb_key_enc"`   // base64
	HashNonce     string `json:"hash_nonce"`       // base64
	MetadataEnc   string `json:"metadata_enc"`     // base64 — encrypted metadata blob
	MetadataNonce string `json:"metadata_nonce"`   // base64
	CreatedAt     string `json:"created_at"`
}

// UploadMeta is the metadata sent by the client when initiating an upload.
// The sensitive fields are inside metadata_enc (encrypted by the client).
type UploadMeta struct {
	MediaID       string `json:"media_id"`        // client-generated UUID, used as AAD for key encryption
	ChunkCount    int    `json:"chunk_count"`
	FileKeyEnc    string `json:"file_key_enc"`    // base64
	ThumbKeyEnc   string `json:"thumb_key_enc"`   // base64
	HashNonce     string `json:"hash_nonce"`       // base64
	MetadataEnc   string `json:"metadata_enc"`     // base64 — encrypted metadata blob
	MetadataNonce string `json:"metadata_nonce"`   // base64
	CreatedAt     string `json:"created_at,omitempty"` // optional: preserve original timestamp on rotate
}

func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func FromB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
