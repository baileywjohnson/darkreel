package media

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/baileywjohnson/darkreel/internal/auth"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type Handler struct {
	DB      *sql.DB
	Storage *storage.Layout
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
	mediaID := chi.URLParam(r, "id")

	item, err := db.GetMedia(h.DB, mediaID, userID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAPIItem(item))
}

const (
	maxThumbnailSize = 2 << 20   // 2 MB
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
	if err := json.NewDecoder(part).Decode(&meta); err != nil {
		http.Error(w, "invalid metadata", http.StatusBadRequest)
		return
	}
	part.Close()

	if meta.ChunkCount <= 0 || meta.ChunkCount > maxChunkCount {
		http.Error(w, fmt.Sprintf("chunk_count must be between 1 and %d", maxChunkCount), http.StatusBadRequest)
		return
	}

	mediaID := uuid.New().String()
	if err := h.Storage.EnsureMediaDir(userID, mediaID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Read thumbnail part
	part, err = mr.NextPart()
	if err != nil || part.FormName() != "thumbnail" {
		http.Error(w, "second part must be thumbnail", http.StatusBadRequest)
		return
	}
	thumbData, err := io.ReadAll(io.LimitReader(part, maxThumbnailSize))
	if err != nil {
		http.Error(w, "failed to read thumbnail", http.StatusBadRequest)
		return
	}
	part.Close()

	if err := h.Storage.WriteThumbnail(userID, mediaID, thumbData); err != nil {
		h.Storage.RemoveMedia(userID, mediaID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Read chunk parts
	chunkIndex := 0
	for {
		part, err = mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.Storage.RemoveMedia(userID, mediaID)
			http.Error(w, "failed to read chunk", http.StatusBadRequest)
			return
		}

		chunkData, err := io.ReadAll(io.LimitReader(part, maxChunkSize))
		if err != nil {
			h.Storage.RemoveMedia(userID, mediaID)
			http.Error(w, "failed to read chunk data", http.StatusBadRequest)
			return
		}
		part.Close()

		if err := h.Storage.WriteChunk(userID, mediaID, chunkIndex, chunkData); err != nil {
			h.Storage.RemoveMedia(userID, mediaID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		chunkIndex++
	}

	if chunkIndex != meta.ChunkCount {
		h.Storage.RemoveMedia(userID, mediaID)
		http.Error(w, fmt.Sprintf("expected %d chunks, got %d", meta.ChunkCount, chunkIndex), http.StatusBadRequest)
		return
	}

	fileKeyBytes, _ := FromB64(meta.FileKeyEnc)
	thumbKeyBytes, _ := FromB64(meta.ThumbKeyEnc)
	hashNonceBytes, _ := FromB64(meta.HashNonce)
	metadataEncBytes, _ := FromB64(meta.MetadataEnc)
	metadataNonceBytes, _ := FromB64(meta.MetadataNonce)

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
		h.Storage.RemoveMedia(userID, mediaID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": mediaID})
}

func (h *Handler) GetChunk(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := chi.URLParam(r, "id")
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
		http.Error(w, "chunk index out of range", http.StatusBadRequest)
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
	mediaID := chi.URLParam(r, "id")

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
	mediaID := chi.URLParam(r, "id")

	if _, err := db.GetMedia(h.DB, mediaID, userID); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if err := h.Storage.RemoveMedia(userID, mediaID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := db.DeleteMedia(h.DB, mediaID, userID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	userID := auth.GetUserID(r)
	mediaID := chi.URLParam(r, "id")

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
	mediaID := chi.URLParam(r, "id")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req struct {
		MetadataEnc   string `json:"metadata_enc"`
		MetadataNonce string `json:"metadata_nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	encBytes, _ := FromB64(req.MetadataEnc)
	nonceBytes, _ := FromB64(req.MetadataNonce)
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

	encBytes, _ := FromB64(req.FolderTreeEnc)
	nonceBytes, _ := FromB64(req.FolderTreeNonce)
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
