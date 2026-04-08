package crypto

import (
	"bytes"
	"testing"
)

func TestBlockEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("hello darkreel encryption")
	aad := []byte("test-context-id")

	enc, err := EncryptBlock(plaintext, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptBlock(enc, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, dec) {
		t.Fatalf("round-trip failed: got %q, want %q", dec, plaintext)
	}

	// Decrypting with wrong AAD should fail
	_, err = DecryptBlock(enc, key, []byte("wrong-context"))
	if err == nil {
		t.Fatal("expected error decrypting with wrong AAD")
	}

	// Decrypting with nil AAD should fail (was encrypted with non-nil AAD)
	_, err = DecryptBlock(enc, key, nil)
	if err == nil {
		t.Fatal("expected error decrypting with nil AAD when encrypted with non-nil AAD")
	}
}

func TestChunkEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 10)
	}

	// Test multiple chunks with different indices
	for i := 0; i < 5; i++ {
		plaintext := bytes.Repeat([]byte{byte(i)}, 1024)
		enc, err := EncryptChunk(plaintext, key, i)
		if err != nil {
			t.Fatalf("chunk %d encrypt: %v", i, err)
		}
		dec, err := DecryptChunk(enc, key, i)
		if err != nil {
			t.Fatalf("chunk %d decrypt: %v", i, err)
		}
		if !bytes.Equal(plaintext, dec) {
			t.Fatalf("chunk %d round-trip failed", i)
		}
	}
}

func TestChunkWrongIndex(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("test data for AAD check")

	enc, err := EncryptChunk(plaintext, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Decrypting with wrong chunk index should fail (AAD mismatch)
	_, err = DecryptChunk(enc, key, 1)
	if err == nil {
		t.Fatal("expected error decrypting with wrong chunk index")
	}
}

func TestKeyEncryptDecrypt(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 20)
	}
	mediaID := []byte("550e8400-e29b-41d4-a716-446655440000")

	fileKey, err := GenerateFileKey()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := EncryptKey(fileKey, masterKey, mediaID)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptKey(enc, masterKey, mediaID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileKey, dec) {
		t.Fatal("key round-trip failed")
	}

	// Decrypting with wrong media ID should fail
	_, err = DecryptKey(enc, masterKey, []byte("different-media-id"))
	if err == nil {
		t.Fatal("expected error decrypting file key with wrong media ID")
	}
}

func TestPasswordHashVerify(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	password := "testpassword123"
	hash := HashPassword(password, salt)

	if !VerifyPassword(password, salt, hash) {
		t.Fatal("password verification failed")
	}
	if VerifyPassword("wrongpassword", salt, hash) {
		t.Fatal("wrong password should not verify")
	}
}

func TestHashModification(t *testing.T) {
	nonce, err := GenerateHashNonce()
	if err != nil {
		t.Fatal(err)
	}

	// Test JPEG modification
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	modified, err := ModifyHash(jpeg, "image/jpeg", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(jpeg, modified) {
		t.Fatal("JPEG hash modification should change the data")
	}
	// Verify SOI marker preserved
	if modified[0] != 0xFF || modified[1] != 0xD8 {
		t.Fatal("JPEG SOI marker should be preserved")
	}

	// Test PNG modification
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		// IHDR chunk (minimal)
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00,
		0x90, 0x77, 0x53, 0xDE,
		// IDAT chunk
		0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54,
		0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
		0xE2, 0x21, 0xBC, 0x33,
	}
	modifiedPNG, err := ModifyHash(png, "image/png", nonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(png, modifiedPNG) {
		t.Fatal("PNG hash modification should change the data")
	}
}

func TestSessionKeyDerivation(t *testing.T) {
	salt := []byte("test-salt-1234567890123456789012")
	key := DeriveSessionKey("testpassword", salt)
	if len(key) != 32 {
		t.Fatalf("session key should be 32 bytes, got %d", len(key))
	}
	// Same password + salt should produce same key
	key2 := DeriveSessionKey("testpassword", salt)
	if !bytes.Equal(key, key2) {
		t.Fatal("deterministic derivation failed")
	}
	// Different salt should produce different key
	salt2 := []byte("different-salt-12345678901234567")
	key3 := DeriveSessionKey("testpassword", salt2)
	if bytes.Equal(key, key3) {
		t.Fatal("different salts should produce different keys")
	}
}
