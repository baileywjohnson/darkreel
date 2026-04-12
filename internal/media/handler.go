package media

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/baileywjohnson/darkreel/internal/auth"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const maxConcurrentUploads = 3 // per-user concurrent upload limit

type Handler struct {
	DB              *sql.DB
	Storage         *storage.Layout
	Shredder        *storage.Shredder // async secure file deletion
	MaxStorageBytes int64              // per-user storage quota in bytes (0 = unlimited)

	uploadMu   sync.Mutex
	uploadSems map[string]chan struct{} // per-user upload semaphores
}

// acquireUpload blocks until an upload slot is available for the user.
// Returns false if the handler has not been initialized (should not happen).
func (h *Handler) acquireUpload(userID string) {
	h.uploadMu.Lock()
	if h.uploadSems == nil {
		h.uploadSems = make(map[string]chan struct{})
	}
	sem, ok := h.uploadSems[userID]
	if !ok {
		sem = make(chan struct{}, maxConcurrentUploads)
		h.uploadSems[userID] = sem
	}
	h.uploadMu.Unlock()
	sem <- struct{}{} // blocks if maxConcurrentUploads slots are taken
}

func (h *Handler) releaseUpload(userID string) {
	h.uploadMu.Lock()
	sem := h.uploadSems[userID]
	h.uploadMu.Unlock()
	<-sem
}

// validID returns the URL param if it is a valid UUID, or writes a 400 and returns "".
func validID(w http.ResponseWriter, r *http.Request, param string) string {
	id := chi.URLParam(r, param)
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return ""
	}
	return id
}

// QuotaCheck returns the authenticated user's effective quota and current usage (in bytes).
func (h *Handler) QuotaCheck(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)

	quota := h.MaxStorageBytes
	if val, err := db.GetSetting(h.DB, "default_storage_quota"); err == nil {
		if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
			quota = n
		}
	}
	if user, err := db.GetUserByID(h.DB, userID); err == nil && user.StorageQuota > 0 {
		quota = user.StorageQuota
	}

	used, err := db.GetUserStorageBytes(h.DB, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"quota": quota, "used": used})
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := (page - 1) * limit

	items, total, err := db.ListMedia(h.DB, userID, limit, offset)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	apiItems := make([]APIMediaItem, len(items))
	for i, m := range items {
		apiItems[i] = toAPIItem(m)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"items": apiItems,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := validID(w, r, "id")
	if mediaID == "" {
		return
	}

	item, err := db.GetMedia(h.DB, mediaID, userID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAPIItem(item))
}

const (
	maxThumbnailSize = 256 * 1024 // must match storage.paddedThumbSize to prevent truncation
	maxChunkSize     = 20 << 20  // 20 MB (large fMP4 segments + GCM overhead)
	maxChunkCount    = 50000     // ~50 GB at 1MB chunks
	maxRequestSize   = 100 << 30 // 100 GB hard limit
)

func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)

	// Per-user concurrency limit to prevent disk exhaustion via parallel uploads
	h.acquireUpload(userID)
	defer h.releaseUpload(userID)

	// Limit total request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	// Parse multipart: first part is JSON metadata, subsequent parts are chunks
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart upload", http.StatusBadRequest)
		return
	}

	// First part: metadata
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "metadata" {
		http.Error(w, "first part must be metadata", http.StatusBadRequest)
		return
	}

	var meta UploadMeta
	if err := json.NewDecoder(io.LimitReader(part, 1<<20)).Decode(&meta); err != nil { // 1 MB max for metadata JSON
		http.Error(w, "invalid metadata", http.StatusBadRequest)
		return
	}
	part.Close()

	if meta.ChunkCount <= 0 || meta.ChunkCount > maxChunkCount {
		http.Error(w, fmt.Sprintf("chunk_count must be between 1 and %d", maxChunkCount), http.StatusBadRequest)
		return
	}

	// Client generates media ID so it can use it as AAD during encryption
	if meta.MediaID == "" {
		http.Error(w, "media_id is required", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(meta.MediaID); err != nil {
		http.Error(w, "media_id must be a valid UUID", http.StatusBadRequest)
		return
	}
	mediaID := meta.MediaID

	// Decode all metadata fields before any I/O to fail fast on bad input
	fileKeyBytes, err := FromB64(meta.FileKeyEnc)
	if err != nil {
		http.Error(w, "invalid file_key_enc", http.StatusBadRequest)
		return
	}
	thumbKeyBytes, err := FromB64(meta.ThumbKeyEnc)
	if err != nil {
		http.Error(w, "invalid thumb_key_enc", http.StatusBadRequest)
		return
	}
	hashNonceBytes, err := FromB64(meta.HashNonce)
	if err != nil {
		http.Error(w, "invalid hash_nonce", http.StatusBadRequest)
		return
	}
	metadataEncBytes, err := FromB64(meta.MetadataEnc)
	if err != nil {
		http.Error(w, "invalid metadata_enc", http.StatusBadRequest)
		return
	}
	metadataNonceBytes, err := FromB64(meta.MetadataNonce)
	if err != nil {
		http.Error(w, "invalid metadata_nonce", http.StatusBadRequest)
		return
	}

	// Validate decoded blob sizes to prevent DB bloat via oversized metadata.
	// file_key_enc / thumb_key_enc: AES-256-GCM(32-byte key) = 12 nonce + 32 ct + 16 tag = 60 bytes
	// hash_nonce: 32 bytes, metadata_nonce: 12 bytes (GCM nonce)
	// metadata_enc: encrypted JSON (filename, type, dims, etc.) — cap at 64 KB
	const maxKeyEncLen = 128       // generous headroom over expected 60 bytes
	const maxNonceLen = 64         // generous headroom over expected 12-32 bytes
	const maxMetadataEncLen = 65536 // 64 KB
	if len(fileKeyBytes) > maxKeyEncLen || len(thumbKeyBytes) > maxKeyEncLen {
		http.Error(w, "encrypted key too large", http.StatusBadRequest)
		return
	}
	if len(hashNonceBytes) > maxNonceLen || len(metadataNonceBytes) > maxNonceLen {
		http.Error(w, "nonce too large", http.StatusBadRequest)
		return
	}
	if len(metadataEncBytes) > maxMetadataEncLen {
		http.Error(w, "encrypted metadata too large", http.StatusBadRequest)
		return
	}

	// Per-user storage quota check (bytes). Single query fetches user override,
	// server default, and current usage to avoid multiple DB round trips.
	// Priority: per-user DB override > server default in DB > env var fallback.
	qi, err := db.GetQuotaInfo(h.DB, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	quota := h.MaxStorageBytes // env var fallback
	if qi.DefaultQuota > 0 {
		quota = qi.DefaultQuota
	}
	if qi.UserQuota > 0 {
		quota = qi.UserQuota
	}
	if quota <= 0 {
		http.Error(w, "No storage quota configured. Please contact your administrator.", http.StatusForbidden)
		return
	}
	// Pre-check: reject if already at or over quota before writing any chunks.
	if qi.UsedBytes >= quota {
		http.Error(w, "Storage quota exceeded. Please contact your administrator.", http.StatusForbidden)
		return
	}

	// INSERT DB record first — fails fast on duplicate media_id (PRIMARY KEY
	// constraint), preventing a race where two concurrent uploads with the same
	// ID both write to disk and one cleanup deletes the other's files.
	// SizeBytes is set to 0 initially and updated after all chunks are read.
	mediaItem := &db.MediaItem{
		ID:            mediaID,
		UserID:        userID,
		ChunkCount:    meta.ChunkCount,
		FileKeyEnc:    fileKeyBytes,
		ThumbKeyEnc:   thumbKeyBytes,
		HashNonce:     hashNonceBytes,
		MetadataEnc:   metadataEncBytes,
		MetadataNonce: metadataNonceBytes,
	}
	if err := db.InsertMedia(h.DB, mediaItem); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// From here, any failure must clean up both DB record and files.
	cleanup := func() {
		db.DeleteMedia(h.DB, mediaID, userID)
		h.Storage.RemoveMedia(userID, mediaID)
	}

	if err := h.Storage.EnsureMediaDir(userID, mediaID); err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Read thumbnail part
	part, err = mr.NextPart()
	if err != nil || part.FormName() != "thumbnail" {
		cleanup()
		http.Error(w, "second part must be thumbnail", http.StatusBadRequest)
		return
	}
	thumbData, err := io.ReadAll(io.LimitReader(part, maxThumbnailSize+1))
	if err != nil {
		cleanup()
		http.Error(w, "failed to read thumbnail", http.StatusBadRequest)
		return
	}
	if int64(len(thumbData)) > maxThumbnailSize {
		cleanup()
		http.Error(w, "thumbnail exceeds maximum size", http.StatusBadRequest)
		return
	}
	part.Close()

	if err := h.Storage.WriteThumbnail(userID, mediaID, thumbData); err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Stream chunk parts directly to disk, tracking total bytes for quota enforcement.
	// Each chunk is streamed without buffering the entire chunk in memory.
	chunkIndex := 0
	var totalBytes int64
	for {
		part, err = mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			http.Error(w, "failed to read chunk", http.StatusBadRequest)
			return
		}

		// Enforce chunk count during the loop to prevent disk exhaustion
		// from a client sending more chunks than declared in metadata.
		if chunkIndex >= meta.ChunkCount {
			part.Close()
			cleanup()
			http.Error(w, "too many chunks", http.StatusBadRequest)
			return
		}

		n, err := h.Storage.WriteChunkFromReader(userID, mediaID, chunkIndex, part, maxChunkSize)
		part.Close()
		if err != nil {
			cleanup()
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if n == 0 {
			cleanup()
			http.Error(w, "empty chunk not allowed", http.StatusBadRequest)
			return
		}

		totalBytes += int64(n)
		chunkIndex++
	}

	if chunkIndex != meta.ChunkCount {
		cleanup()
		http.Error(w, fmt.Sprintf("expected %d chunks, got %d", meta.ChunkCount, chunkIndex), http.StatusBadRequest)
		return
	}

	// Fsync the media directory once after all chunks are written,
	// ensuring durability without the overhead of per-chunk fsync.
	if err := h.Storage.SyncMediaDir(userID, mediaID); err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Quantize size to 256 KB buckets to reduce content fingerprinting
	// precision in the database. Negligible impact on quota accuracy.
	const sizeQuantum = 256 * 1024
	quantizedBytes := ((totalBytes + sizeQuantum - 1) / sizeQuantum) * sizeQuantum

	// Atomically verify quota and update size in a single transaction
	// to close the TOCTOU window between concurrent uploads.
	ok, err := db.UpdateMediaSizeWithQuotaCheck(h.DB, mediaID, userID, quantizedBytes, quota)
	if err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		cleanup()
		http.Error(w, "Storage quota exceeded. Please contact your administrator.", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": mediaID})
}

func (h *Handler) GetChunk(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := validID(w, r, "id")
	if mediaID == "" {
		return
	}
	indexStr := chi.URLParam(r, "index")
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 {
		http.Error(w, "invalid chunk index", http.StatusBadRequest)
		return
	}

	// Verify ownership
	item, err := db.GetMedia(h.DB, mediaID, userID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if index >= item.ChunkCount {
		// Use same error as missing media to avoid leaking whether the item exists
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Stream the full padded chunk so Content-Length reveals only the bucket
	// size (1/2/4/8/16 MB), not the real encrypted chunk size. The client
	// reads the 4-byte length prefix and strips the padding.
	// Streamed directly from disk to avoid buffering entire chunks in memory.
	f, size, err := h.Storage.ReadChunkPaddedFile(userID, mediaID, index)
	if err != nil {
		http.Error(w, "chunk not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	io.Copy(w, f)
}

func (h *Handler) GetThumbnail(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := validID(w, r, "id")
	if mediaID == "" {
		return
	}

	// Verify ownership
	if _, err := db.GetMedia(h.DB, mediaID, userID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Stream the full padded thumbnail so Content-Length is always the fixed
	// padded size (256 KB), preventing thumbnail size fingerprinting.
	// Streamed directly from disk to avoid buffering in memory.
	f, size, err := h.Storage.ReadThumbnailPaddedFile(userID, mediaID)
	if err != nil {
		http.Error(w, "thumbnail not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	io.Copy(w, f)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := validID(w, r, "id")
	if mediaID == "" {
		return
	}

	if _, err := db.GetMedia(h.DB, mediaID, userID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Delete DB record first, then queue async shred. The file key is now
	// gone from the DB, making the encrypted data on disk unrecoverable.
	// If the server crashes before shredding completes, startup orphan
	// cleanup handles the leftover files.
	if err := db.DeleteMedia(h.DB, mediaID, userID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.Shredder.QueueMedia(userID, mediaID)
	w.WriteHeader(http.StatusNoContent)
}

// UpdateMetadata allows the client to update an item's encrypted metadata
// (e.g., to assign a folder). The server never decrypts it.
func (h *Handler) UpdateMetadata(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := validID(w, r, "id")
	if mediaID == "" {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		MetadataEnc   string `json:"metadata_enc"`
		MetadataNonce string `json:"metadata_nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	encBytes, err := FromB64(req.MetadataEnc)
	if err != nil {
		http.Error(w, "invalid metadata_enc encoding", http.StatusBadRequest)
		return
	}
	nonceBytes, err := FromB64(req.MetadataNonce)
	if err != nil {
		http.Error(w, "invalid metadata_nonce encoding", http.StatusBadRequest)
		return
	}
	if len(encBytes) == 0 || len(nonceBytes) == 0 {
		http.Error(w, "invalid metadata", http.StatusBadRequest)
		return
	}

	if err := db.UpdateMediaMetadata(h.DB, mediaID, userID, encBytes, nonceBytes); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetFolders returns the user's encrypted folder tree.
func (h *Handler) GetFolders(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)

	data, err := db.GetUserData(h.DB, userID)
	if err != nil {
		// No folder tree yet — return empty
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"folder_tree_enc": nil, "folder_tree_nonce": nil})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"folder_tree_enc":   B64(unpadFolderTree(data.FolderTreeEnc)),
		"folder_tree_nonce": B64(data.FolderTreeNonce),
	})
}

// SaveFolders saves the user's encrypted folder tree.
func (h *Handler) SaveFolders(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max for folder tree
	var req struct {
		FolderTreeEnc   string `json:"folder_tree_enc"`
		FolderTreeNonce string `json:"folder_tree_nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	encBytes, err := FromB64(req.FolderTreeEnc)
	if err != nil {
		http.Error(w, "invalid folder_tree_enc encoding", http.StatusBadRequest)
		return
	}
	nonceBytes, err := FromB64(req.FolderTreeNonce)
	if err != nil {
		http.Error(w, "invalid folder_tree_nonce encoding", http.StatusBadRequest)
		return
	}
	if len(encBytes) == 0 || len(nonceBytes) == 0 {
		http.Error(w, "invalid folder tree", http.StatusBadRequest)
		return
	}

	// Pad the encrypted folder tree to a power-of-2 KB bucket to prevent
	// the blob size from revealing folder structure complexity.
	paddedEnc := padFolderTree(encBytes)

	if err := db.SaveUserData(h.DB, userID, paddedEnc, nonceBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// padFolderTree pads encrypted folder tree data to a power-of-2 KB bucket.
// Format: [4 bytes big-endian real length][data][random padding]
func padFolderTree(data []byte) []byte {
	bucket := 1024 // 1 KB minimum
	needed := 4 + len(data)
	for bucket < needed {
		bucket *= 2
	}
	padded := make([]byte, bucket)
	padded[0] = byte(len(data) >> 24)
	padded[1] = byte(len(data) >> 16)
	padded[2] = byte(len(data) >> 8)
	padded[3] = byte(len(data))
	copy(padded[4:], data)
	// Fill padding with random bytes so a DB-level attacker cannot distinguish
	// padding from encrypted data and infer the exact folder tree size.
	if padStart := 4 + len(data); padStart < bucket {
		storage.FillPadding(padded[padStart:])
	}
	return padded
}

// unpadFolderTree strips the padding from a padded folder tree blob.
func unpadFolderTree(padded []byte) []byte {
	if len(padded) < 4 {
		return padded
	}
	realLen := int(padded[0])<<24 | int(padded[1])<<16 | int(padded[2])<<8 | int(padded[3])
	if realLen <= 0 || 4+realLen > len(padded) {
		return padded // not padded (legacy data), return as-is
	}
	return padded[4 : 4+realLen]
}

func toAPIItem(m *db.MediaItem) APIMediaItem {
	return APIMediaItem{
		ID:            m.ID,
		FileKeyEnc:    B64(m.FileKeyEnc),
		ThumbKeyEnc:   B64(m.ThumbKeyEnc),
		HashNonce:     B64(m.HashNonce),
		MetadataEnc:   B64(m.MetadataEnc),
		MetadataNonce: B64(m.MetadataNonce),
		CreatedAt:     m.CreatedAt,
	}
}
