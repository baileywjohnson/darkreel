package media

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/baileywjohnson/darkreel/internal/auth"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type Handler struct {
	DB              *sql.DB
	Storage         *storage.Layout
	MaxStorageBytes int // per-user storage quota in bytes (0 = unlimited)
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
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
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
	json.NewEncoder(w).Encode(map[string]int{"quota": quota, "used": used})
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

	// Per-user storage quota check (bytes). We do a pre-check using an estimate
	// based on chunk count, then update with the actual size after reading all chunks.
	// Priority: per-user DB override > server default in DB > env var fallback.
	quota := h.MaxStorageBytes // env var fallback
	if val, err := db.GetSetting(h.DB, "default_storage_quota"); err == nil {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			quota = n
		}
	}
	if user, err := db.GetUserByID(h.DB, userID); err == nil && user.StorageQuota > 0 {
		quota = user.StorageQuota
	}
	if quota <= 0 {
		http.Error(w, "No storage quota configured. Please contact your administrator.", http.StatusForbidden)
		return
	}
	existingBytes, err := db.GetUserStorageBytes(h.DB, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Pre-check: reject if already at or over quota before writing any chunks.
	if existingBytes >= quota {
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
	thumbData, err := io.ReadAll(io.LimitReader(part, maxThumbnailSize))
	if err != nil {
		cleanup()
		http.Error(w, "failed to read thumbnail", http.StatusBadRequest)
		return
	}
	part.Close()

	if err := h.Storage.WriteThumbnail(userID, mediaID, thumbData); err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Read chunk parts, tracking total bytes for quota enforcement.
	chunkIndex := 0
	totalBytes := 0
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

		chunkData, err := io.ReadAll(io.LimitReader(part, maxChunkSize))
		if err != nil {
			cleanup()
			http.Error(w, "failed to read chunk data", http.StatusBadRequest)
			return
		}
		part.Close()

		if len(chunkData) == 0 {
			cleanup()
			http.Error(w, "empty chunk not allowed", http.StatusBadRequest)
			return
		}

		totalBytes += len(chunkData)

		if err := h.Storage.WriteChunk(userID, mediaID, chunkIndex, chunkData); err != nil {
			cleanup()
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		chunkIndex++
	}

	if chunkIndex != meta.ChunkCount {
		cleanup()
		http.Error(w, fmt.Sprintf("expected %d chunks, got %d", meta.ChunkCount, chunkIndex), http.StatusBadRequest)
		return
	}

	// Re-read current usage to close the TOCTOU window: another concurrent
	// upload may have completed between our initial read and now.
	currentBytes, err := db.GetUserStorageBytes(h.DB, userID)
	if err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if currentBytes+totalBytes > quota {
		cleanup()
		http.Error(w, "Storage quota exceeded. Please contact your administrator.", http.StatusForbidden)
		return
	}

	// Update the media record with the actual size.
	if err := db.UpdateMediaSize(h.DB, mediaID, totalBytes); err != nil {
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
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

	rc, size, err := h.Storage.ReadChunkStream(userID, mediaID, index)
	if err != nil {
		http.Error(w, "chunk not found", http.StatusNotFound)
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	io.Copy(w, rc)
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

	data, err := h.Storage.ReadThumbnail(userID, mediaID)
	if err != nil {
		http.Error(w, "thumbnail not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Write(data)
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

	// Delete DB record first, then shred storage. If the server crashes between
	// these steps, orphaned storage is cleaned up at startup.
	if err := db.DeleteMedia(h.DB, mediaID, userID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := h.Storage.RemoveMedia(userID, mediaID); err != nil {
		log.Printf("Warning: failed to remove storage for %s/%s: %v", userID, mediaID, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")

	// Stream all encrypted chunks sequentially
	for i := 0; i < item.ChunkCount; i++ {
		rc, _, err := h.Storage.ReadChunkStream(userID, mediaID, i)
		if err != nil {
			log.Printf("Warning: download truncated for %s/%s at chunk %d/%d: %v", userID, mediaID, i, item.ChunkCount, err)
			return // connection already started, can't send error
		}
		io.Copy(w, rc)
		rc.Close()
	}
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
		"folder_tree_enc":   B64(data.FolderTreeEnc),
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

	if err := db.SaveUserData(h.DB, userID, encBytes, nonceBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func toAPIItem(m *db.MediaItem) APIMediaItem {
	return APIMediaItem{
		ID:            m.ID,
		ChunkCount:    m.ChunkCount,
		FileKeyEnc:    B64(m.FileKeyEnc),
		ThumbKeyEnc:   B64(m.ThumbKeyEnc),
		HashNonce:     B64(m.HashNonce),
		MetadataEnc:   B64(m.MetadataEnc),
		MetadataNonce: B64(m.MetadataNonce),
		CreatedAt:     m.CreatedAt,
	}
}
