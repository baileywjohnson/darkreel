package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/baileywjohnson/darkreel/internal/auth"
	"github.com/baileywjohnson/darkreel/internal/db"
	"github.com/baileywjohnson/darkreel/internal/server"
	"github.com/baileywjohnson/darkreel/internal/storage"
)

//go:embed web/*
var webFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "./data", "data directory for encrypted files and database")
	flag.Parse()

	database, err := db.Open(*dataDir)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	store := storage.NewLayout(*dataDir)

	// Bootstrap admin user on first run
	userCount, err := db.GetUserCount(database)
	if err != nil {
		log.Fatalf("Failed to check user count: %v", err)
	}
	if userCount == 0 {
		adminUser := os.Getenv("DARKREEL_ADMIN_USERNAME")
		adminPass := os.Getenv("DARKREEL_ADMIN_PASSWORD")
		if adminUser == "" {
			adminUser = "admin"
		}
		if adminPass == "" {
			log.Fatal("DARKREEL_ADMIN_PASSWORD must be set for first-run admin bootstrap")
		}
		recoveryCode, err := auth.BootstrapAdmin(database, adminUser, adminPass)
		if err != nil {
			log.Fatalf("Failed to create admin user: %v", err)
		}
		log.Printf("Admin user %q created", adminUser)
		fmt.Fprintf(os.Stderr, "\n========================================\n")
		fmt.Fprintf(os.Stderr, "  RECOVERY CODE — save this now!\n")
		fmt.Fprintf(os.Stderr, "  %s\n", recoveryCode)
		fmt.Fprintf(os.Stderr, "========================================\n\n")
	}

	// Clean up orphaned data directories not referenced in DB.
	// Abort if DB queries fail — incomplete valid-paths would cause data loss.
	validPaths := make(map[string]bool)
	userIDs, err := db.ListUserIDs(database)
	if err != nil {
		log.Printf("Warning: orphan cleanup skipped — failed to list users: %v", err)
	} else {
		allOK := true
		for _, uid := range userIDs {
			mediaIDs, err := db.ListMediaIDsByUser(database, uid)
			if err != nil {
				log.Printf("Warning: orphan cleanup skipped — failed to list media for user %s: %v", uid, err)
				allOK = false
				break
			}
			for _, mid := range mediaIDs {
				validPaths[uid+"/"+mid] = true
			}
		}
		if allOK {
			if removed, err := store.CleanupOrphans(validPaths); err != nil {
				log.Printf("Warning: orphan cleanup failed: %v", err)
			} else if removed > 0 {
				log.Printf("Cleaned up %d orphaned media directories", removed)
			}
		}
	}

	// Clean up incomplete uploads — DB records whose chunk files are missing
	// (e.g., server crashed after DB INSERT but before all chunks were written).
	if summaries, err := db.ListAllMediaSummaries(database); err != nil {
		log.Printf("Warning: incomplete upload cleanup skipped — failed to list media: %v", err)
	} else {
		cleaned := 0
		for _, s := range summaries {
			if !store.IsMediaComplete(s.UserID, s.ID, s.ChunkCount) {
				store.RemoveMedia(s.UserID, s.ID)
				db.DeleteMediaByID(database, s.ID)
				cleaned++
			}
		}
		if cleaned > 0 {
			log.Printf("Cleaned up %d incomplete uploads", cleaned)
		}
	}

	// Start session cleanup goroutine (removes expired sessions every minute)
	auth.Sessions.StartCleanup()

	maxChunks := 0 // 0 = unlimited
	if v := os.Getenv("MAX_STORAGE_CHUNKS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxChunks = n
		}
	}

	srv := &server.Server{
		DB:                database,
		Storage:           store,
		WebFS:             webFS,
		Addr:              *addr,
		PersistSession:    os.Getenv("PERSIST_SESSION") != "false",
		AllowRegistration: os.Getenv("ALLOW_REGISTRATION") == "true", // default false
		TrustProxy:        os.Getenv("TRUST_PROXY") == "true",        // default false — only enable behind a reverse proxy
		MaxStorageChunks:  maxChunks,
	}

	// Graceful shutdown: drain in-flight requests, then close DB
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down — draining connections...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
		}
	}()

	if err := srv.Run(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Shutdown complete")
}
