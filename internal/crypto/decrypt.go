package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// DecryptBlock decrypts a small block (e.g., a file key) encrypted with EncryptBlock.
// The aad parameter must match the value used during encryption.
func DecryptBlock(ciphertext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, aad)
}

// DecryptChunk decrypts a single encrypted chunk.
// The mediaID and chunkIndex must match the values used during encryption.
func DecryptChunk(ciphertext, key []byte, chunkIndex int, mediaID string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return DecryptChunkWith(gcm, ciphertext, chunkIndex, mediaID)
}

// DecryptChunkWith decrypts a chunk using a pre-initialized GCM cipher.
func DecryptChunkWith(gcm cipher.AEAD, ciphertext []byte, chunkIndex int, mediaID string) ([]byte, error) {
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	aad := chunkAAD(mediaID, chunkIndex)

	return gcm.Open(nil, nonce, ct, aad)
}
