package server

import (
	"database/sql"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
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
}

func (s *Server) Run() error {
	r := s.routes()
	log.Printf("Darkreel listening on %s", s.Addr)
	return http.ListenAndServe(s.Addr, r)
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(securityHeaders)
	r.Use(RateLimit(100, time.Minute)) // Global: 100 req/min per IP

	authHandler := &auth.Handler{DB: s.DB, Storage: s.Storage}
	mediaHandler := &media.Handler{DB: s.DB, Storage: s.Storage}

	// Auth rate limiter: 5 attempts per minute per IP
	authLimiter := RateLimit(5, time.Minute)

	// Public config endpoint
	persistSession := s.PersistSession
	allowRegistration := s.AllowRegistration
	r.Get("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"persistSession":    persistSession,
			"allowRegistration": allowRegistration,
		})
	})

	// Public routes (with strict rate limiting)
	if s.AllowRegistration {
		r.With(authLimiter).Post("/api/auth/register", authHandler.Register)
	} else {
		r.Post("/api/auth/register", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "registration is disabled", http.StatusForbidden)
		})
	}
	r.With(authLimiter).Post("/api/auth/login", authHandler.Login)
	r.With(authLimiter).Post("/api/auth/recover", authHandler.Recover)

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)

		r.Post("/api/auth/logout", authHandler.Logout)

		r.Get("/api/media", mediaHandler.List)
		r.Get("/api/media/{id}", mediaHandler.Get)
		r.Post("/api/media/upload", mediaHandler.Upload)
		r.Delete("/api/media/{id}", mediaHandler.Delete)
		r.Get("/api/media/{id}/chunk/{index}", mediaHandler.GetChunk)
		r.Get("/api/media/{id}/thumbnail", mediaHandler.GetThumbnail)
		r.Get("/api/media/{id}/download", mediaHandler.Download)
	})

	// Admin routes (authenticated + admin only)
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware)
		r.Use(auth.AdminMiddleware)

		r.Get("/api/admin/users", authHandler.ListUsers)
		r.Post("/api/admin/users", authHandler.CreateUser)
		r.Delete("/api/admin/users/{id}", authHandler.DeleteUser)
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob:; media-src 'self' blob:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
