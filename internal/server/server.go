package server

import (
	"database/sql"
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/baileywjohnson/darkreel/internal/auth"
	"github.com/baileywjohnson/darkreel/internal/media"
	"github.com/baileywjohnson/darkreel/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	DB      *sql.DB
	Storage *storage.Layout
	WebFS   embed.FS
	Addr    string
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

	authHandler := &auth.Handler{DB: s.DB}
	mediaHandler := &media.Handler{DB: s.DB, Storage: s.Storage}

	// Public routes
	r.Post("/api/auth/register", authHandler.Register)
	r.Post("/api/auth/login", authHandler.Login)

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
