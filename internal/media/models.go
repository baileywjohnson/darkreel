package media

import "encoding/base64"

// APIMediaItem is the JSON representation of a media item returned to clients.
// All three *KeySealed fields are libsodium sealed boxes (80 bytes each)
// wrapping the AES key used to encrypt the corresponding blob with the user's
// X25519 public key. The browser opens them with its private key; PPVDA never
// opens them (it doesn't have the private key) and only writes them on upload.
// chunk_count is deliberately omitted — the client reads it from the encrypted
// metadata to avoid leaking approximate file size to network observers.
type APIMediaItem struct {
	ID                string `json:"id"`
	FileKeySealed     string `json:"file_key_sealed"`     // base64, 80-byte sealed box
	ThumbKeySealed    string `json:"thumb_key_sealed"`    // base64, 80-byte sealed box
	MetadataKeySealed string `json:"metadata_key_sealed"` // base64, 80-byte sealed box
	HashNonce         string `json:"hash_nonce"`
	MetadataEnc       string `json:"metadata_enc"`   // base64 — metadata encrypted under metadata key
	MetadataNonce     string `json:"metadata_nonce"`
	CreatedAt         string `json:"created_at"`
}

// UploadMeta is the metadata sent by the client when initiating an upload.
// Each of the three symmetric keys (file, thumb, metadata) is provided as a
// sealed box addressed to the uploading user's X25519 public key.
type UploadMeta struct {
	MediaID           string `json:"media_id"` // client-generated UUID, used as AAD for content encryption
	ChunkCount        int    `json:"chunk_count"`
	FileKeySealed     string `json:"file_key_sealed"`     // base64
	ThumbKeySealed    string `json:"thumb_key_sealed"`    // base64
	MetadataKeySealed string `json:"metadata_key_sealed"` // base64
	HashNonce         string `json:"hash_nonce"`
	MetadataEnc       string `json:"metadata_enc"`
	MetadataNonce     string `json:"metadata_nonce"`
	CreatedAt         string `json:"created_at,omitempty"` // optional: preserve original timestamp on rotate
}

func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func FromB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
