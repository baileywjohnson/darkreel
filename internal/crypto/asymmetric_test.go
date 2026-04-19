package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeypair_SizesAndClamping(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if len(pub) != X25519PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pub), X25519PublicKeySize)
	}
	if len(priv) != X25519PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(priv), X25519PrivateKeySize)
	}
	// Clamp bits per RFC 7748 §5: priv[0]&=248, priv[31]&=127, priv[31]|=64
	if priv[0]&7 != 0 {
		t.Errorf("private key byte 0 low bits not clamped: %x", priv[0])
	}
	if priv[31]&128 != 0 {
		t.Errorf("private key byte 31 high bit not clamped: %x", priv[31])
	}
	if priv[31]&64 == 0 {
		t.Errorf("private key byte 31 bit 6 not set: %x", priv[31])
	}
}

func TestSealBox_RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// 32-byte payload = the real workload (wrapping an AES file key).
	msg := bytes.Repeat([]byte{0xAB}, 32)
	sealed, err := SealBox(msg, pub)
	if err != nil {
		t.Fatalf("SealBox: %v", err)
	}

	// Expected size: ephemeral pubkey (32) + AES-GCM nonce (12) + payload (32)
	// + AES-GCM tag (16) = 92 bytes.
	if got, want := len(sealed), SealBoxOverhead+len(msg); got != want {
		t.Errorf("sealed length = %d, want %d", got, want)
	}

	plain, err := OpenSealedBox(sealed, pub, priv)
	if err != nil {
		t.Fatalf("OpenSealedBox: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Errorf("round-trip mismatch: got %x want %x", plain, msg)
	}
}

func TestSealBox_WrongRecipientFails(t *testing.T) {
	pubA, _, _ := GenerateKeypair()
	_, privB, _ := GenerateKeypair()
	// sealed to A, opened with B's private key — must fail
	msg := []byte("secret")
	sealed, err := SealBox(msg, pubA)
	if err != nil {
		t.Fatalf("SealBox: %v", err)
	}
	if _, err := OpenSealedBox(sealed, pubA, privB); err == nil {
		t.Fatal("opened sealed box with wrong private key, expected auth failure")
	}
}

func TestSealBox_TamperingFails(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	msg := bytes.Repeat([]byte{0x42}, 32) // 32-byte payload, realistic file-key size

	// Table: one case per distinct byte region so any future regression that
	// stops authenticating a region surfaces here. Every region is covered by
	// AES-GCM except the ephemeral pubkey, which is covered indirectly: a
	// flipped eph_pk produces a different ECDH shared secret and the AES-GCM
	// tag check fails.
	cases := []struct {
		name    string
		flipIdx func(n int) int
	}{
		{"ephemeral pubkey", func(n int) int { return 0 }},
		{"nonce", func(n int) int { return sealEphPubKeySize }},
		{"ciphertext body", func(n int) int { return sealEphPubKeySize + sealNonceSize }},
		{"auth tag", func(n int) int { return n - 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sealed, err := SealBox(msg, pub)
			if err != nil {
				t.Fatalf("SealBox: %v", err)
			}
			sealed[c.flipIdx(len(sealed))] ^= 0x01
			if _, err := OpenSealedBox(sealed, pub, priv); err == nil {
				t.Fatalf("opened tampered sealed box (flipped %s), expected auth failure", c.name)
			}
		})
	}
}

func TestSealBox_TruncationFails(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	sealed, err := SealBox([]byte("msg"), pub)
	if err != nil {
		t.Fatalf("SealBox: %v", err)
	}
	// Truncating anywhere must fail — the AES-GCM tag covers the whole ct.
	for trunc := len(sealed) - 1; trunc >= SealBoxOverhead; trunc-- {
		if _, err := OpenSealedBox(sealed[:trunc], pub, priv); err == nil {
			t.Fatalf("opened truncated sealed box (len=%d), expected auth failure", trunc)
		}
	}
}

func TestSealBox_RejectsWrongKeySizes(t *testing.T) {
	msg := []byte("x")
	if _, err := SealBox(msg, []byte("short")); err == nil {
		t.Error("SealBox accepted short recipient public key")
	}

	pub, priv, _ := GenerateKeypair()
	sealed, _ := SealBox(msg, pub)
	if _, err := OpenSealedBox(sealed, []byte("short"), priv); err == nil {
		t.Error("OpenSealedBox accepted short recipient public key")
	}
	if _, err := OpenSealedBox(sealed, pub, []byte("short")); err == nil {
		t.Error("OpenSealedBox accepted short recipient private key")
	}
	if _, err := OpenSealedBox([]byte("too-short"), pub, priv); err == nil {
		t.Error("OpenSealedBox accepted truncated sealed box")
	}
}

func TestSealBox_FreshPerCall(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	msg := []byte("same-message")
	a, _ := SealBox(msg, pub)
	b, _ := SealBox(msg, pub)
	// Each call uses a fresh ephemeral keypair, so outputs must differ.
	if bytes.Equal(a, b) {
		t.Error("two seal operations produced identical output — ephemeral key reused?")
	}
	// In particular, the first 32 bytes (ephemeral pubkey) must differ.
	if bytes.Equal(a[:32], b[:32]) {
		t.Error("two seal operations used the same ephemeral pubkey")
	}
}
