package media

import "encoding/base64"

// APIMediaItem is the JSON representation of a media item returned to clients.
// All three *KeySealed fields are X25519 sealed boxes (92 bytes each:
// ephemeral key 32 + nonce 12 + AES key 32 + tag 16; see crypto.SealBox)
// sealing the AES key of the corresponding blob to the user's X25519 public
// key. The browser opens them with its private key; PPVDA never
// opens them (it doesn't have the private key) and only writes them on upload.
// chunk_count is deliberately omitted — the client reads it from the encrypted
// metadata to avoid leaking approximate file size to network observers.
type APIMediaItem struct {
	ID                string `json:"id"`
	FileKeySealed     string `json:"file_key_sealed"`     // base64, 92-byte sealed box
	ThumbKeySealed    string `json:"thumb_key_sealed"`    // base64, 92-byte sealed box
	MetadataKeySealed string `json:"metadata_key_sealed"` // base64, 92-byte sealed box
	MetadataEnc       string `json:"metadata_enc"`        // base64 — metadata encrypted under metadata key
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
	// HashNonce is accepted from older clients and discarded. Clients embed
	// a random nonce in image bytes before encryption; storing that same
	// nonce in plaintext here turned every downloaded copy of an image into
	// a beacon linking it back to this account and media item.
	HashNonce     string `json:"hash_nonce,omitempty"`
	MetadataEnc   string `json:"metadata_enc"`
	MetadataNonce string `json:"metadata_nonce"`
	CreatedAt     string `json:"created_at,omitempty"` // optional: preserve original timestamp on rotate
}

func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func FromB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
