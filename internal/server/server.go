package server

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/baileywjohnson/darkreel/internal/auth"
	"github.com/baileywjohnson/darkreel/internal/media"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	DB                *sql.DB
	Storage           *storage.Layout
	WebFS             embed.FS
	Addr              string
	PersistSession    bool
	AllowRegistration bool
	httpServer        *http.Server
}

func (s *Server) Run() error {
	r := s.routes()
	s.httpServer = &http.Server{
		Addr:    s.Addr,
		Handler: r,
	}
	log.Printf("Darkreel listening on %s", s.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully drains in-flight requests before returning.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(securityHeaders)
	r.Use(RateLimit(6000, time.Minute)) // Global: 6000 req/min per IP (high for chunk streaming)

	authHandler := &auth.Handler{DB: s.DB, Storage: s.Storage}
	mediaHandler := &media.Handler{DB: s.DB, Storage: s.Storage}

	// Auth rate limiter: 5 attempts per minute per IP
	authLimiter := RateLimit(5, time.Minute)

	// Registration state — mutable by admins at runtime
	type regState struct {
		sync.RWMutex
		allowed bool
	}
	registration := &regState{allowed: s.AllowRegistration}

	// Health check (no auth, no rate limit)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := s.DB.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "database unavailable"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Public config endpoint
	persistSession := s.PersistSession
	r.Get("/api/config", func(w http.ResponseWriter, r *http.Request) {
		registration.RLock()
		allowed := registration.allowed
		registration.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"persistSession":    persistSession,
			"allowRegistration": allowed,
		})
	})

	// Public routes (with strict rate limiting)
	r.With(authLimiter).Post("/api/auth/register", func(w http.ResponseWriter, r *http.Request) {
		registration.RLock()
		allowed := registration.allowed
		registration.RUnlock()
		if !allowed {
			http.Error(w, "registration is disabled", http.StatusForbidden)
			return
		}
		authHandler.Register(w, r)
	})
	r.With(authLimiter).Post("/api/auth/login", authHandler.Login)
	r.With(authLimiter).Post("/api/auth/recover", authHandler.Recover)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)

		r.Post("/api/auth/logout", authHandler.Logout)
		r.Post("/api/auth/change-password", authHandler.ChangePassword)
		r.Delete("/api/auth/account", authHandler.DeleteOwnAccount)

		r.Get("/api/media", mediaHandler.List)
		r.Get("/api/media/{id}", mediaHandler.Get)
		r.Post("/api/media/upload", mediaHandler.Upload)
		r.Delete("/api/media/{id}", mediaHandler.Delete)
		r.Get("/api/media/{id}/chunk/{index}", mediaHandler.GetChunk)
		r.Get("/api/media/{id}/thumbnail", mediaHandler.GetThumbnail)
		r.Get("/api/media/{id}/download", mediaHandler.Download)
		r.Patch("/api/media/{id}", mediaHandler.UpdateMetadata)

		r.Get("/api/folders", mediaHandler.GetFolders)
		r.Put("/api/folders", mediaHandler.SaveFolders)
	})

	// Admin routes (authenticated + admin only)
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Use(auth.AdminMiddleware)

		r.Get("/api/admin/users", authHandler.ListUsers)
		r.Post("/api/admin/users", authHandler.CreateUser)
		r.Delete("/api/admin/users/{id}", authHandler.DeleteUser)

		r.Post("/api/admin/registration", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Enabled bool `json:"enabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			registration.Lock()
			registration.allowed = req.Enabled
			registration.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled})
		})
	})

	// Serve frontend — SPA fallback
	webRoot, err := fs.Sub(s.WebFS, "web")
	if err != nil {
		log.Fatal("failed to get web sub filesystem:", err)
	}
	fileServer := http.FileServer(http.FS(webRoot))

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		if f, err := webRoot.Open(path[1:]); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})

	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// COEP + COOP enable SharedArrayBuffer for future use and defense-in-depth.
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob:")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		// Prevent caching of API responses containing sensitive data
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store, private")
		}
		next.ServeHTTP(w, r)
	})
}
