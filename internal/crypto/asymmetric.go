package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// X25519 key / sealed-box sizes.
const (
	X25519PublicKeySize  = 32
	X25519PrivateKeySize = 32
	// SealBox output is ephemeral pubkey (32) + NaCl box overhead (16) + message.
	SealBoxOverhead = 32 + box.Overhead
)

// GenerateKeypair returns a new X25519 keypair. The private key is clamped per
// the X25519 spec so it's safe to use directly with curve25519.
func GenerateKeypair() ([]byte, []byte, error) {
	priv := make([]byte, X25519PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, fmt.Errorf("generate x25519 private key: %w", err)
	}
	// Clamp per RFC 7748 §5.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive x25519 public key: %w", err)
	}
	return pub, priv, nil
}

// SealBox encrypts msg to recipientPub using the libsodium crypto_box_seal
// format: ephemeral_pk || box(msg, nonce, recipient_pk, ephemeral_sk) where
// nonce = BLAKE2b-24(ephemeral_pk || recipient_pk). The sender is anonymous —
// only the recipient (holder of the matching private key) can decrypt.
//
// Output length: 32 (ephemeral_pk) + 16 (MAC) + len(msg).
//
// Browser callers use libsodium.js's crypto_box_seal, which produces an
// identical format so outputs are interchangeable.
func SealBox(msg, recipientPub []byte) ([]byte, error) {
	if len(recipientPub) != X25519PublicKeySize {
		return nil, fmt.Errorf("sealbox: recipient public key must be %d bytes, got %d", X25519PublicKeySize, len(recipientPub))
	}

	ephPub, ephPriv, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("sealbox: ephemeral keypair: %w", err)
	}
	// Best-effort zero of the ephemeral private key once we're done with it.
	defer func() {
		for i := range ephPriv {
			ephPriv[i] = 0
		}
	}()

	nonce, err := sealNonce(ephPub, recipientPub)
	if err != nil {
		return nil, err
	}

	var recipArr, ephPrivArr [32]byte
	copy(recipArr[:], recipientPub)
	copy(ephPrivArr[:], ephPriv)

	out := make([]byte, 0, SealBoxOverhead+len(msg))
	out = append(out, ephPub...)
	out = box.Seal(out, msg, &nonce, &recipArr, &ephPrivArr)
	return out, nil
}

// OpenSealedBox reverses SealBox. The server never opens sealed boxes in
// production — this exists for tests and possible future server-side
// integrity tooling (e.g., a migration script with a supplied private key).
func OpenSealedBox(sealed, recipientPub, recipientPriv []byte) ([]byte, error) {
	if len(sealed) < SealBoxOverhead {
		return nil, fmt.Errorf("sealbox: input too short (%d bytes, minimum %d)", len(sealed), SealBoxOverhead)
	}
	if len(recipientPub) != X25519PublicKeySize {
		return nil, fmt.Errorf("sealbox: recipient public key must be %d bytes", X25519PublicKeySize)
	}
	if len(recipientPriv) != X25519PrivateKeySize {
		return nil, fmt.Errorf("sealbox: recipient private key must be %d bytes", X25519PrivateKeySize)
	}

	ephPub := sealed[:32]
	ciphertext := sealed[32:]

	nonce, err := sealNonce(ephPub, recipientPub)
	if err != nil {
		return nil, err
	}

	var ephPubArr, recipPrivArr [32]byte
	copy(ephPubArr[:], ephPub)
	copy(recipPrivArr[:], recipientPriv)

	msg, ok := box.Open(nil, ciphertext, &nonce, &ephPubArr, &recipPrivArr)
	if !ok {
		return nil, fmt.Errorf("sealbox: authentication failed")
	}
	return msg, nil
}

// sealNonce derives the deterministic 24-byte nonce used by crypto_box_seal:
// BLAKE2b-192(ephemeral_pk || recipient_pk).
func sealNonce(ephPub, recipientPub []byte) ([24]byte, error) {
	var nonce [24]byte
	h, err := blake2b.New(24, nil)
	if err != nil {
		return nonce, fmt.Errorf("sealbox: blake2b init: %w", err)
	}
	h.Write(ephPub)
	h.Write(recipientPub)
	copy(nonce[:], h.Sum(nil))
	return nonce, nil
}
