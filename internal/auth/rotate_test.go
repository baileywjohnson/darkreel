package auth

import (
	"bytes"
	"crypto/hmac"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/baileywjohnson/darkreel/internal/crypto"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"github.com/google/uuid"
)

const (
	testUser    = "alice"
	testOldPass = "Old-Passw0rd-1234!"
	testNewPass = "New-Passw0rd-5678!"
)

type testEnv struct {
	t       *testing.T
	db      *sql.DB
	h       *Handler
	mux     *http.ServeMux
	userID  string
	rcode   string // current recovery code (base64url)
	oldPub  []byte
	oldPriv []byte
	oldMK   []byte
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	database, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	rcode, err := BootstrapAdmin(database, testUser, testOldPass)
	if err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	user, err := db.GetUserByUsername(database, testUser)
	if err != nil {
		t.Fatal(err)
	}
	kdfKey := crypto.DeriveKey(testOldPass, user.KDFSalt)
	mk, err := crypto.DecryptBlock(user.EncryptedMK, kdfKey, []byte(user.ID))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := crypto.DecryptBlock(user.EncryptedPrivKey, mk, []byte(user.ID))
	if err != nil {
		t.Fatal(err)
	}

	h := &Handler{
		DB:              database,
		AccountLimiter:  NewAccountLimiter(10, 15*time.Minute),
		RecoveryLimiter: NewAccountLimiter(10, 15*time.Minute),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", h.Login)
	mux.HandleFunc("POST /recover", h.Recover)
	mux.Handle("POST /change-password", Middleware(database)(http.HandlerFunc(h.ChangePassword)))
	mux.Handle("POST /upload", Middleware(database)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	return &testEnv{t: t, db: database, h: h, mux: mux, userID: user.ID, rcode: rcode,
		oldPub: user.PublicKey, oldPriv: priv, oldMK: mk}
}

func (e *testEnv) post(path, token string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	out := map[string]string{}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 %q: %v", s, err)
	}
	return b
}

// clientKeys does what the browser does with a login / change-password
// response: derive the session key from the password, unwrap the master key,
// then unwrap the private key and check it matches the public key.
func clientKeys(t *testing.T, resp map[string]string, userID, password string) (mk, pub, priv []byte) {
	t.Helper()
	sessionKey := crypto.DeriveSessionKey(password, b64(t, resp["kdf_salt"]))
	mk, err := crypto.DecryptBlock(b64(t, resp["encrypted_master_key"]), sessionKey, []byte(userID))
	if err != nil {
		t.Fatalf("unwrap master key: %v", err)
	}
	pub = b64(t, resp["public_key"])
	priv, err = crypto.DecryptBlock(b64(t, resp["encrypted_priv_key"]), mk, []byte(userID))
	if err != nil {
		t.Fatalf("unwrap private key with new master key: %v", err)
	}
	derived, _ := crypto.PublicKeyFromPrivate(priv)
	if !bytes.Equal(derived, pub) {
		t.Fatal("private key does not match public key")
	}
	return mk, pub, priv
}

// testItem is a media row the test inserts, with the plaintext keys kept so
// re-sealing can be checked.
type testItem struct {
	id                      string
	fileKey, thumbKey, mKey []byte
	metaPlain               []byte
}

// insertItem seals three fresh keys to pub and stores a row. withTag adds an
// owner_tag computed like the client does (tagMK = nil forges a bad tag).
func (e *testEnv) insertItem(pub []byte, withTag bool, tagMK []byte) *testItem {
	e.t.Helper()
	it := &testItem{id: uuid.New().String()}
	var sealed [3][]byte
	for i, k := range []*[]byte{&it.fileKey, &it.thumbKey, &it.mKey} {
		*k, _ = crypto.GenerateFileKey()
		s, err := crypto.SealBox(*k, pub)
		if err != nil {
			e.t.Fatal(err)
		}
		sealed[i] = s
	}
	mk := &db.MediaKeys{ID: it.id, FileKeySealed: sealed[0], ThumbKeySealed: sealed[1], MetadataKeySealed: sealed[2]}

	meta := map[string]any{"name": "holiday <1>.jpg", "type": "image", "folderId": nil}
	if withTag {
		tag := make([]byte, 32) // wrong tag unless tagMK is given
		if tagMK != nil {
			ok, _ := deriveOwnerKey(tagMK)
			tag = ownerTag(ok, mk)
		}
		meta["owner_tag"] = base64.StdEncoding.EncodeToString(tag)
	}
	plain, _ := json.Marshal(meta)
	plain = append(plain, bytes.Repeat([]byte(" "), 256-len(plain))...) // client space-pads
	it.metaPlain = plain
	enc, err := crypto.EncryptBlock(plain, it.mKey, []byte(it.id))
	if err != nil {
		e.t.Fatal(err)
	}

	if err := db.InsertMedia(e.db, &db.MediaItem{
		ID: it.id, UserID: e.userID, ChunkCount: 1, SizeBytes: 1,
		FileKeySealed: sealed[0], ThumbKeySealed: sealed[1], MetadataKeySealed: sealed[2],
		HashNonce: []byte{}, MetadataEnc: enc[12:], MetadataNonce: enc[:12],
	}); err != nil {
		e.t.Fatal(err)
	}
	return it
}

func (e *testEnv) login(password string) (*httptest.ResponseRecorder, map[string]string) {
	rec := e.post("/login", "", map[string]string{"username": testUser, "password": password})
	if rec.Code != http.StatusOK {
		return rec, nil
	}
	return rec, decodeJSON(e.t, rec)
}

// checkRotated asserts every item's sealed keys open only with newPriv and
// still yield the original keys, and that owner tags were handled correctly.
func (e *testEnv) checkRotated(items []*testItem, tagged map[string]bool, oldPub, oldPriv, newPub, newPriv, newMK []byte) {
	t := e.t
	t.Helper()
	newOwner, _ := deriveOwnerKey(newMK)
	for _, it := range items {
		m, err := db.GetMedia(e.db, it.id, e.userID)
		if err != nil {
			t.Fatal(err)
		}
		for name, pair := range map[string][2][]byte{
			"file":  {m.FileKeySealed, it.fileKey},
			"thumb": {m.ThumbKeySealed, it.thumbKey},
			"meta":  {m.MetadataKeySealed, it.mKey},
		} {
			got, err := crypto.OpenSealedBox(pair[0], newPub, newPriv)
			if err != nil {
				t.Fatalf("%s %s key does not open with new private key: %v", it.id, name, err)
			}
			if !bytes.Equal(got, pair[1]) {
				t.Fatalf("%s %s key changed by re-seal", it.id, name)
			}
			if _, err := crypto.OpenSealedBox(pair[0], oldPub, oldPriv); err == nil {
				t.Fatalf("%s %s key still opens with the old private key", it.id, name)
			}
		}

		plain, err := crypto.DecryptBlock(append(bytes.Clone(m.MetadataNonce), m.MetadataEnc...), it.mKey, []byte(it.id))
		if err != nil {
			t.Fatalf("metadata no longer decrypts: %v", err)
		}
		if len(plain) != len(it.metaPlain) {
			t.Fatalf("metadata length changed: %d -> %d", len(it.metaPlain), len(plain))
		}
		var meta map[string]any
		if err := json.Unmarshal(plain, &meta); err != nil {
			t.Fatalf("metadata not JSON after rotation: %v (%q)", err, plain)
		}
		if meta["name"] != "holiday <1>.jpg" {
			t.Fatalf("metadata name changed: %v", meta["name"])
		}
		tagStr, hasTag := meta["owner_tag"].(string)
		switch {
		case !hasTag:
			if !bytes.Equal(plain, it.metaPlain) {
				t.Fatal("untagged metadata was modified")
			}
		case tagged[it.id]:
			want := ownerTag(newOwner, &db.MediaKeys{ID: it.id, FileKeySealed: m.FileKeySealed,
				ThumbKeySealed: m.ThumbKeySealed, MetadataKeySealed: m.MetadataKeySealed})
			if !hmac.Equal(b64(t, tagStr), want) {
				t.Fatal("owner_tag was not recomputed for the new master key / sealed keys")
			}
		default:
			if !bytes.Equal(plain, it.metaPlain) {
				t.Fatal("metadata with an invalid owner_tag was re-tagged")
			}
		}
	}
}

func TestChangePasswordRotatesKeys(t *testing.T) {
	e := newTestEnv(t)

	good := e.insertItem(e.oldPub, true, e.oldMK)
	plain := e.insertItem(e.oldPub, false, nil)
	forged := e.insertItem(e.oldPub, true, nil)
	items := []*testItem{good, plain, forged}
	tagged := map[string]bool{good.id: true}

	// A sealed box for someone else's key: can't be opened, must be left alone.
	strangerPub, _, _ := crypto.GenerateKeypair()
	stranger := e.insertItem(strangerPub, false, nil)
	strangerBefore, _ := db.GetMedia(e.db, stranger.id, e.userID)

	// Folder tree under the old master key, stored padded like SaveFolders.
	tree := []byte(`[{"id":"f1","name":"Trips","parentId":null}]`)
	enc, _ := crypto.EncryptBlock(tree, e.oldMK, []byte(e.userID))
	if err := db.SaveUserData(e.db, e.userID, storage.PadFolderTree(enc[12:]), enc[:12], e.oldPub); err != nil {
		t.Fatal(err)
	}

	// A delegation (with an access token) and an unexchanged code.
	delegationID := uuid.New().String()
	if _, err := e.db.Exec(`INSERT INTO delegations (id, user_id, client_name, client_url, scope, refresh_token_hash, created_at)
		VALUES (?, ?, 'app', 'https://app', 'upload', ?, '2026-01-01')`, delegationID, e.userID, db.HashRefreshToken("rt")); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDelegationCode(e.db, &db.DelegationCode{Code: "c1", UserID: e.userID, ClientName: "app",
		ClientURL: "https://app", Scope: "upload", ExpiresAt: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	delegTok, _ := GenerateDelegationToken(e.userID, delegationID, time.Hour)
	if rec := e.post("/upload", delegTok, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delegation token rejected before rotation: %d", rec.Code)
	}

	_, loginResp := e.login(testOldPass)
	if loginResp == nil {
		t.Fatal("login with old password failed")
	}

	rec := e.post("/change-password", loginResp["token"], map[string]string{
		"old_password": testOldPass, "new_password": testNewPass,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", rec.Code, rec.Body.String())
	}
	cp := decodeJSON(t, rec)
	newMK, newPub, newPriv := clientKeys(t, cp, e.userID, testNewPass)
	if bytes.Equal(newPub, e.oldPub) || bytes.Equal(newMK, e.oldMK) || bytes.Equal(newPriv, e.oldPriv) {
		t.Fatal("master key / keypair were not rotated")
	}

	e.checkRotated(items, tagged, e.oldPub, e.oldPriv, newPub, newPriv, newMK)

	strangerAfter, _ := db.GetMedia(e.db, stranger.id, e.userID)
	if !bytes.Equal(strangerAfter.FileKeySealed, strangerBefore.FileKeySealed) ||
		!bytes.Equal(strangerAfter.MetadataEnc, strangerBefore.MetadataEnc) {
		t.Fatal("row that did not open with the old key was modified")
	}

	// Folder tree now decrypts with the new master key only.
	ud, err := db.GetUserData(e.db, e.userID)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(bytes.Clone(ud.FolderTreeNonce), storage.UnpadFolderTree(ud.FolderTreeEnc)...)
	if got, err := crypto.DecryptBlock(combined, newMK, []byte(e.userID)); err != nil || !bytes.Equal(got, tree) {
		t.Fatalf("folder tree not re-encrypted under new master key: %v", err)
	}
	if _, err := crypto.DecryptBlock(combined, e.oldMK, []byte(e.userID)); err == nil {
		t.Fatal("folder tree still decrypts with old master key")
	}

	// Delegations, codes and the old session are gone; the delegation's
	// access token stops working immediately (D17).
	var n int
	e.db.QueryRow(`SELECT (SELECT COUNT(*) FROM delegations) + (SELECT COUNT(*) FROM delegation_codes)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d delegations/codes survived the password change", n)
	}
	if rec := e.post("/upload", delegTok, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("delegation token still accepted after password change: %d", rec.Code)
	}
	if rec := e.post("/upload", loginResp["token"], nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old session token still accepted: %d", rec.Code)
	}
	if rec := e.post("/upload", cp["token"], nil); rec.Code != http.StatusNoContent {
		t.Fatalf("new session token rejected: %d", rec.Code)
	}

	// Writes conditioned on the old public key are refused.
	late := &db.MediaItem{ID: uuid.New().String(), UserID: e.userID, ChunkCount: 1,
		FileKeySealed: []byte{1}, ThumbKeySealed: []byte{1}, MetadataKeySealed: []byte{1},
		HashNonce: []byte{}, MetadataEnc: []byte{1}, MetadataNonce: []byte{1}}
	if err := db.InsertMediaForKey(e.db, late, e.oldPub); !errors.Is(err, db.ErrKeysChanged) {
		t.Fatalf("insert sealed to the old key: got %v, want ErrKeysChanged", err)
	}
	if err := db.SaveUserData(e.db, e.userID, []byte{1}, []byte{1}, e.oldPub); !errors.Is(err, db.ErrKeysChanged) {
		t.Fatalf("folder save under the old key: got %v, want ErrKeysChanged", err)
	}

	// A fresh login returns the new public key, and its private key unwraps
	// under the new master key.
	if rec, _ := e.login(testOldPass); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old password still logs in: %d", rec.Code)
	}
	_, relogin := e.login(testNewPass)
	if relogin == nil {
		t.Fatal("login with new password failed")
	}
	mk2, pub2, _ := clientKeys(t, relogin, e.userID, testNewPass)
	if !bytes.Equal(pub2, newPub) || !bytes.Equal(mk2, newMK) {
		t.Fatal("login after change returns different keys from the change-password response")
	}

	// The pre-change recovery code no longer works; the new one does.
	if rec := e.post("/recover", "", map[string]string{"username": testUser,
		"recovery_code": e.rcode, "new_password": "Another-Passw0rd-9!"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("old recovery code accepted after password change: %d", rec.Code)
	}
	if cp["recovery_code"] == "" || cp["recovery_code"] == e.rcode {
		t.Fatal("recovery code not rotated")
	}
}

func TestRecoverRotatesKeys(t *testing.T) {
	e := newTestEnv(t)
	good := e.insertItem(e.oldPub, true, e.oldMK)
	plain := e.insertItem(e.oldPub, false, nil)

	rec := e.post("/recover", "", map[string]string{
		"username": testUser, "recovery_code": e.rcode, "new_password": testNewPass,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("recover: %d %s", rec.Code, rec.Body.String())
	}
	newCode := decodeJSON(t, rec)["recovery_code"]

	_, lr := e.login(testNewPass)
	if lr == nil {
		t.Fatal("login after recovery failed")
	}
	newMK, newPub, newPriv := clientKeys(t, lr, e.userID, testNewPass)
	if bytes.Equal(newPub, e.oldPub) || bytes.Equal(newMK, e.oldMK) {
		t.Fatal("recovery did not rotate keys")
	}
	e.checkRotated([]*testItem{good, plain}, map[string]bool{good.id: true}, e.oldPub, e.oldPriv, newPub, newPriv, newMK)

	// The recovery-code-wrapped copies hold the new keys.
	user, _ := db.GetUserByID(e.db, e.userID)
	code, _ := base64.URLEncoding.DecodeString(newCode)
	rmk, err := crypto.DecryptMasterKeyWithRecovery(user.RecoveryMK, code, []byte(e.userID))
	if err != nil || !bytes.Equal(rmk, newMK) {
		t.Fatal("recovery_mk does not wrap the new master key")
	}
	rpriv, err := crypto.DecryptBlock(user.RecoveryPrivKey, code, []byte(e.userID))
	if err != nil || !bytes.Equal(rpriv, newPriv) {
		t.Fatal("recovery_priv_key does not wrap the new private key")
	}

	// The used code is spent.
	if rec := e.post("/recover", "", map[string]string{"username": testUser,
		"recovery_code": e.rcode, "new_password": testNewPass}); rec.Code != http.StatusBadRequest {
		t.Fatalf("spent recovery code accepted: %d", rec.Code)
	}
}

func TestRotationConflict(t *testing.T) {
	e := newTestEnv(t)
	user, _ := db.GetUserByID(e.db, e.userID)
	a, err := prepareKeyRotation(e.db, user, e.oldMK, testNewPass)
	if err != nil {
		t.Fatal(err)
	}
	defer a.wipe()
	b, err := prepareKeyRotation(e.db, user, e.oldMK, testNewPass)
	if err != nil {
		t.Fatal(err)
	}
	defer b.wipe()
	if err := a.commit(e.db, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.commit(e.db, nil); !errors.Is(err, db.ErrKeysChanged) {
		t.Fatalf("second concurrent rotation: got %v, want ErrKeysChanged", err)
	}
}

// Rows inserted after the rotation was prepared, but before it commits, are
// re-sealed inside the transaction.
func TestRotationCoversLateRows(t *testing.T) {
	e := newTestEnv(t)
	user, _ := db.GetUserByID(e.db, e.userID)
	rot, err := prepareKeyRotation(e.db, user, e.oldMK, testNewPass)
	if err != nil {
		t.Fatal(err)
	}
	defer rot.wipe()
	late := e.insertItem(e.oldPub, true, e.oldMK)
	if err := rot.commit(e.db, nil); err != nil {
		t.Fatal(err)
	}
	e.checkRotated([]*testItem{late}, map[string]bool{late.id: true}, e.oldPub, e.oldPriv,
		rot.keys.PublicKey, rot.newPriv, rot.newMK)
}

func TestFindOwnerTag(t *testing.T) {
	cases := map[string]bool{
		`{"a":{"owner_tag":"x"},"owner_tag":"abc"}   `: true,
		`{"owner_tag":"abc","owner_tag":"def"}`:        false,
		`{"name":"owner_tag"}`:                         false,
		`["owner_tag","abc"]`:                          false,
		`{"owner_tag" : "abc" , "b":[1,2]}`:            true,
	}
	for doc, want := range cases {
		start, end, val, found := findOwnerTag([]byte(doc))
		if found != want {
			t.Errorf("%s: found=%v want %v", doc, found, want)
			continue
		}
		if found && (val != "abc" || doc[start:end] != `"abc"`) {
			t.Errorf("%s: got %q span %q", doc, val, doc[start:end])
		}
	}
}
