package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// X25519 key + sealed-box sizes.
//
// SealBox format (Web Crypto compatible — uses only primitives that browsers
// implement natively, so the SPA requires NO vendored JS dependencies):
//
//     ephemeral_pk (32) || nonce (12) || AES-256-GCM(derived_key, nonce, msg)
//
// where derived_key = HKDF-SHA256(ECDH(ephemeral_sk, recipient_pk),
//                                 salt=empty, info="darkreel-seal-v1")
//
// Overhead for a 32-byte payload: 32 (eph_pk) + 12 (nonce) + 32 (msg) + 16
// (AES-GCM tag) = 92 bytes. Browser seals via Web Crypto's built-in X25519,
// HKDF, and AES-GCM; the server opens via this implementation (only used in
// tests — production Darkreel never opens sealed boxes).
const (
	X25519PublicKeySize  = 32
	X25519PrivateKeySize = 32
	sealEphPubKeySize    = 32
	sealNonceSize        = 12
	sealGCMTagSize       = 16
	// SealBoxOverhead is the non-payload byte count of a sealed box:
	// ephemeral pubkey + AES-GCM nonce + AES-GCM tag. Callers compute the
	// expected on-wire size as SealBoxOverhead + len(payload).
	SealBoxOverhead = sealEphPubKeySize + sealNonceSize + sealGCMTagSize
)

// sealInfo is the HKDF `info` parameter. Versioned so the construction can be
// rotated later without re-using derived keys across formats.
var sealInfo = []byte("darkreel-seal-v1")

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

// SealBox encrypts msg to recipientPub using X25519-ECDH + HKDF-SHA256 +
// AES-256-GCM, producing the wire format above. The sender is anonymous —
// only the recipient (holder of the matching private key) can decrypt.
//
// The browser equivalent is a ~30-line function over Web Crypto's native
// X25519, HKDF, and AES-GCM — NO vendored dependency.
func SealBox(msg, recipientPub []byte) ([]byte, error) {
	if len(recipientPub) != X25519PublicKeySize {
		return nil, fmt.Errorf("sealbox: recipient public key must be %d bytes, got %d", X25519PublicKeySize, len(recipientPub))
	}

	ephPub, ephPriv, err := GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("sealbox: ephemeral keypair: %w", err)
	}
	defer clear(ephPriv)

	gcm, err := deriveSealCipher(ephPriv, recipientPub)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, sealNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("sealbox: nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, msg, nil)

	out := make([]byte, 0, SealBoxOverhead+len(msg))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenSealedBox reverses SealBox. The server never opens sealed boxes in
// production — this exists for tests and any future server-side integrity
// tooling.
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

	ephPub := sealed[:sealEphPubKeySize]
	nonce := sealed[sealEphPubKeySize : sealEphPubKeySize+sealNonceSize]
	ciphertext := sealed[sealEphPubKeySize+sealNonceSize:]

	gcm, err := deriveSealCipher(recipientPriv, ephPub)
	if err != nil {
		return nil, err
	}

	msg, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("sealbox: authentication failed: %w", err)
	}
	return msg, nil
}

// deriveSealCipher computes the ECDH shared secret, runs HKDF-SHA256 over it
// with the static sealInfo, and returns a ready AES-256-GCM AEAD. Works for
// both SealBox (priv=ephemeral, peerPub=recipient) and OpenSealedBox
// (priv=recipient, peerPub=ephemeral) — X25519 ECDH is symmetric.
func deriveSealCipher(priv, peerPub []byte) (cipher.AEAD, error) {
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, fmt.Errorf("sealbox: ecdh: %w", err)
	}
	defer clear(shared)

	// X25519 rejects the all-zero shared secret (low-order points), so a
	// maliciously chosen ephemeral pubkey from an attacker cannot coerce
	// the derived key into a known value.

	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, sealInfo), key); err != nil {
		return nil, fmt.Errorf("sealbox: hkdf: %w", err)
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealbox: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealbox: gcm: %w", err)
	}
	return gcm, nil
}
