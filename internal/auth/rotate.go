package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"golang.org/x/crypto/hkdf"
)

// Password change and recovery replace the account's master key and X25519
// keypair rather than re-wrapping the old ones. Re-wrapping left the keys
// that protect every file unchanged, so anyone holding an older copy of the
// database plus the old password or recovery code (an admin who created the
// account, a leaked backup) kept access to everything, including uploads made
// after the change.
//
// Rotation re-seals each media row's three 92-byte sealed keys to the new
// public key and re-encrypts the folder tree under the new master key. The
// file, thumbnail and metadata keys themselves — and so the ciphertext on
// disk — are unchanged: items uploaded before a rotation stay decryptable by
// someone holding an old database copy and the old password. Rotation
// protects everything uploaded afterwards.

// ownerTagInfo is the HKDF info and HMAC domain prefix of the client's item
// ownership tag (web/js): K = HKDF-SHA256(masterKey, salt="", info) and
// tag = HMAC-SHA256(K, info || mediaID || file_key_sealed ||
// thumb_key_sealed || metadata_key_sealed), base64 in the encrypted metadata
// JSON as "owner_tag". The tag covers the sealed keys and is keyed by the
// master key, so rotation has to recompute it.
const ownerTagInfo = "darkreel-owner-v1"

// keyRotation is a fully prepared replacement of one user's credentials and
// keys. Build it with prepareKeyRotation (slow: Argon2id + per-item X25519),
// then commit it; always wipe it.
type keyRotation struct {
	userID string

	oldPub   []byte
	oldPriv  []byte
	oldMK    []byte
	oldOwner []byte

	newMK    []byte
	newPriv  []byte
	newOwner []byte

	// keys holds the new column values; keys.PublicKey is the new public key.
	keys db.UserKeys
	// recoveryCode is the new recovery code (raw bytes) to hand to the user.
	recoveryCode []byte

	// resealed maps media ID → the row as read before the transaction and its
	// re-sealed replacement. Rows that changed (or appeared) by the time the
	// transaction runs are re-sealed again inside it.
	resealed map[string][2]*db.MediaKeys
}

// prepareKeyRotation generates the new master key, keypair, password hash and
// recovery code for user, and re-seals every media row currently in the
// database. oldMK is the user's current master key (unwrapped by the caller
// with the old password or recovery code); the caller keeps ownership of it.
func prepareKeyRotation(database *sql.DB, user *db.User, oldMK []byte, newPassword string) (*keyRotation, error) {
	uid := []byte(user.ID)
	k := &keyRotation{
		userID:   user.ID,
		oldPub:   bytes.Clone(user.PublicKey),
		oldMK:    bytes.Clone(oldMK),
		resealed: make(map[string][2]*db.MediaKeys),
	}
	ok := false
	defer func() {
		if !ok {
			k.wipe()
		}
	}()

	var err error
	k.oldPriv, err = crypto.DecryptBlock(user.EncryptedPrivKey, oldMK, uid)
	if err != nil {
		return nil, fmt.Errorf("unwrap private key: %w", err)
	}
	// Re-sealing with a private key that doesn't match the stored public key
	// would silently skip every item. Refuse instead.
	derived, err := crypto.PublicKeyFromPrivate(k.oldPriv)
	if err != nil || !bytes.Equal(derived, user.PublicKey) {
		return nil, errors.New("stored private key does not match public key")
	}

	if k.newMK, err = crypto.GenerateFileKey(); err != nil {
		return nil, err
	}
	var newPub []byte
	if newPub, k.newPriv, err = crypto.GenerateKeypair(); err != nil {
		return nil, err
	}
	k.keys.PublicKey = newPub

	if k.keys.AuthSalt, err = crypto.GenerateSalt(); err != nil {
		return nil, err
	}
	if k.keys.KDFSalt, err = crypto.GenerateSalt(); err != nil {
		return nil, err
	}
	k.keys.PasswordHash = crypto.HashPassword(newPassword, k.keys.AuthSalt)

	kdfKey := crypto.DeriveKey(newPassword, k.keys.KDFSalt)
	defer clear(kdfKey)
	if k.keys.EncryptedMK, err = crypto.EncryptBlock(k.newMK, kdfKey, uid); err != nil {
		return nil, err
	}
	if k.keys.EncryptedPrivKey, err = crypto.EncryptBlock(k.newPriv, k.newMK, uid); err != nil {
		return nil, err
	}

	// New recovery code: the old one unwraps only the old keys.
	if k.recoveryCode, err = crypto.GenerateRecoveryCode(); err != nil {
		return nil, err
	}
	if k.keys.RecoveryMK, err = crypto.EncryptMasterKeyForRecovery(k.newMK, k.recoveryCode, uid); err != nil {
		return nil, err
	}
	if k.keys.RecoveryPrivKey, err = crypto.EncryptBlock(k.newPriv, k.recoveryCode, uid); err != nil {
		return nil, err
	}

	if k.oldOwner, err = deriveOwnerKey(k.oldMK); err != nil {
		return nil, err
	}
	if k.newOwner, err = deriveOwnerKey(k.newMK); err != nil {
		return nil, err
	}

	// Do the bulk of the X25519 work before taking the write lock. commit
	// re-reads the rows inside its transaction and only redoes the ones that
	// changed in between.
	rows, err := db.ListMediaKeys(database, user.ID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		next, err := k.resealMedia(row)
		if err != nil {
			return nil, err
		}
		k.resealed[row.ID] = [2]*db.MediaKeys{row, next}
	}

	ok = true
	return k, nil
}

// commit writes the rotation in one transaction: new credentials and keys
// (conditional on the public key being unchanged), every media row re-sealed,
// the folder tree re-encrypted, and all delegations and unexchanged
// delegation codes deleted. beforeCommit runs while the write lock is held,
// just before the commit; callers use it to drop the user's sessions so no
// request authenticated with them can start between commit and cleanup.
//
// Returns sql.ErrNoRows if the user was deleted and db.ErrKeysChanged if
// another rotation committed first.
func (k *keyRotation) commit(database *sql.DB, beforeCommit func()) error {
	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Write first: from this statement on the transaction holds SQLite's
	// write lock, so every media row committed before it is visible to the
	// read below and no upload can insert another until we commit. An upload
	// whose insert loses the race is refused by InsertMediaForKey, since the
	// public key it was authorized against is gone.
	if err := db.ReplaceUserKeysTx(tx, k.userID, k.oldPub, &k.keys); err != nil {
		return err
	}

	rows, err := db.ListMediaKeys(tx, k.userID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		var next *db.MediaKeys
		if pre, ok := k.resealed[row.ID]; ok && pre[0].Equal(row) {
			next = pre[1]
		} else if next, err = k.resealMedia(row); err != nil {
			return err
		}
		if next.Equal(row) {
			continue // nothing opened with the old key; leave the row as-is
		}
		if err := db.UpdateMediaKeysTx(tx, k.userID, next); err != nil {
			return err
		}
	}

	if err := k.reencryptFolderTree(tx); err != nil {
		return err
	}

	// A password change or recovery is an assume-compromise reset: connected
	// apps hold the old public key and must re-authorize, and a code minted
	// before the reset must not be exchangeable after it.
	if err := db.DeleteAllDelegationsForUserTx(tx, k.userID); err != nil {
		return err
	}
	if err := db.DeleteAllDelegationCodesForUserTx(tx, k.userID); err != nil {
		return err
	}

	if beforeCommit != nil {
		beforeCommit()
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// The old wrapped keys and sealed boxes were overwritten in the main
	// file (secure_delete); flush the WAL so its page images go too.
	db.CheckpointWAL(database)
	return nil
}

// resealMedia returns row with its sealed keys re-sealed to the new public
// key and, if its metadata carries a valid ownership tag, the tag recomputed.
// A sealed key that doesn't open with the old private key is kept as-is: the
// item was already unreadable to this user (e.g. sealed to someone else's key
// by a misbehaving client), and failing the rotation over it would let such a
// client block password changes.
func (k *keyRotation) resealMedia(row *db.MediaKeys) (*db.MediaKeys, error) {
	next := &db.MediaKeys{
		ID:                row.ID,
		FileKeySealed:     row.FileKeySealed,
		ThumbKeySealed:    row.ThumbKeySealed,
		MetadataKeySealed: row.MetadataKeySealed,
		MetadataEnc:       row.MetadataEnc,
		MetadataNonce:     row.MetadataNonce,
	}
	reseal := func(sealed []byte) []byte {
		out, err := crypto.ResealBox(sealed, k.oldPub, k.oldPriv, k.keys.PublicKey)
		if err != nil {
			return sealed
		}
		return out
	}
	next.FileKeySealed = reseal(row.FileKeySealed)
	next.ThumbKeySealed = reseal(row.ThumbKeySealed)

	metaKey, err := crypto.OpenSealedBox(row.MetadataKeySealed, k.oldPub, k.oldPriv)
	if err != nil {
		return next, nil
	}
	defer clear(metaKey)
	if next.MetadataKeySealed, err = crypto.SealBox(metaKey, k.keys.PublicKey); err != nil {
		return nil, err
	}
	enc, nonce, err := k.retagMetadata(row, next, metaKey)
	if err != nil {
		return nil, err
	}
	if enc != nil {
		next.MetadataEnc, next.MetadataNonce = enc, nonce
	}
	return next, nil
}

// retagMetadata recomputes the "owner_tag" inside an item's encrypted
// metadata for the new master key and sealed keys. It returns nil (leave the
// metadata alone) when the metadata can't be decrypted, isn't JSON, carries no
// tag, or carries a tag that doesn't verify under the old key — re-tagging an
// invalid tag would turn an item nobody vouched for into a "verified" one.
//
// The metadata key is unchanged; the plaintext is re-encrypted under it with
// a fresh nonce, keeping its exact length (the client space-pads the JSON).
func (k *keyRotation) retagMetadata(old, next *db.MediaKeys, metaKey []byte) (enc, nonce []byte, err error) {
	if len(old.MetadataNonce) != 12 {
		return nil, nil, nil
	}
	aad := []byte(old.ID)
	combined := append(bytes.Clone(old.MetadataNonce), old.MetadataEnc...)
	plain, err := crypto.DecryptBlock(combined, metaKey, aad)
	if err != nil {
		return nil, nil, nil
	}
	defer clear(plain)

	start, end, tagB64, found := findOwnerTag(plain)
	if !found {
		return nil, nil, nil
	}
	oldTag, err := base64.StdEncoding.DecodeString(tagB64)
	if err != nil || !hmac.Equal(oldTag, ownerTag(k.oldOwner, old)) {
		return nil, nil, nil
	}
	newVal, _ := json.Marshal(base64.StdEncoding.EncodeToString(ownerTag(k.newOwner, next)))

	// Splice the new quoted value in place of the old one and restore the
	// original length from the trailing space padding.
	out := make([]byte, 0, len(plain)+len(newVal))
	out = append(out, plain[:start]...)
	out = append(out, newVal...)
	out = append(out, plain[end:]...)
	if len(out) > len(plain) && len(bytes.TrimRight(out, " ")) <= len(plain) {
		out = out[:len(plain)] // only drops trailing padding
	}
	for len(out) < len(plain) {
		out = append(out, ' ')
	}
	defer clear(out)
	if len(out) != len(plain) {
		return nil, nil, nil // can't keep the length; leave untouched
	}

	sealed, err := crypto.EncryptBlock(out, metaKey, aad)
	if err != nil {
		return nil, nil, err
	}
	return sealed[12:], sealed[:12], nil
}

// findOwnerTag locates the string value of the top-level "owner_tag" key in a
// JSON object, returning its byte span (including quotes) and decoded value.
// A document with the key more than once is treated as having none: which
// copy a parser honours differs between implementations.
func findOwnerTag(doc []byte) (start, end int, value string, found bool) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return 0, 0, "", false
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return 0, 0, "", false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, 0, "", false
		}
		if key, _ := keyTok.(string); key != ownerTagKey {
			continue
		}
		if found {
			return 0, 0, "", false
		}
		end = int(dec.InputOffset())
		start = end - len(raw)
		if start < 0 || !bytes.Equal(doc[start:end], raw) {
			return 0, 0, "", false
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, 0, "", false
		}
		found = true
	}
	return start, end, value, found
}

const ownerTagKey = "owner_tag"

// deriveOwnerKey computes the ownership-tag HMAC key from a master key.
func deriveOwnerKey(masterKey []byte) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, masterKey, nil, []byte(ownerTagInfo)), key); err != nil {
		return nil, err
	}
	return key, nil
}

// ownerTag computes the ownership tag of a media row under ownerKey.
func ownerTag(ownerKey []byte, m *db.MediaKeys) []byte {
	mac := hmac.New(sha256.New, ownerKey)
	mac.Write([]byte(ownerTagInfo))
	mac.Write([]byte(m.ID))
	mac.Write(m.FileKeySealed)
	mac.Write(m.ThumbKeySealed)
	mac.Write(m.MetadataKeySealed)
	return mac.Sum(nil)
}

// reencryptFolderTree moves the user's folder tree blob from the old master
// key to the new one, keeping its format: AES-256-GCM with AAD = user ID,
// nonce stored separately, ciphertext padded by storage.PadFolderTree. A blob
// that doesn't decrypt with the old key was already unreadable and is left
// as-is.
func (k *keyRotation) reencryptFolderTree(tx *sql.Tx) error {
	data, err := db.GetUserDataTx(tx, k.userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data.FolderTreeEnc) == 0 || len(data.FolderTreeNonce) == 0 {
		return nil
	}
	uid := []byte(k.userID)
	combined := append(bytes.Clone(data.FolderTreeNonce), storage.UnpadFolderTree(data.FolderTreeEnc)...)
	plain, err := crypto.DecryptBlock(combined, k.oldMK, uid)
	if err != nil {
		return nil
	}
	defer clear(plain)
	enc, err := crypto.EncryptBlock(plain, k.newMK, uid)
	if err != nil {
		return err
	}
	return db.UpdateUserDataTx(tx, k.userID, storage.PadFolderTree(enc[12:]), enc[:12])
}

// wipe zeroes every secret the rotation holds.
func (k *keyRotation) wipe() {
	clear(k.oldPriv)
	clear(k.oldMK)
	clear(k.oldOwner)
	clear(k.newMK)
	clear(k.newPriv)
	clear(k.newOwner)
	clear(k.recoveryCode)
}
