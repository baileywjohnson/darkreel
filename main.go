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
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
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
		log.Printf("Admin user created")

		// Write recovery code to a temp file instead of stderr to avoid
		// it persisting in journald. The file is chmod 0600 and should
		// be read and deleted by the setup script immediately.
		rcPath := filepath.Join(*dataDir, ".recovery-code")
		if err := os.WriteFile(rcPath, []byte(recoveryCode), 0600); err != nil {
			// Fallback to stderr if file write fails
			fmt.Fprintf(os.Stderr, "\n========================================\n")
			fmt.Fprintf(os.Stderr, "  RECOVERY CODE — save this now!\n")
			fmt.Fprintf(os.Stderr, "  %s\n", recoveryCode)
			fmt.Fprintf(os.Stderr, "========================================\n\n")
		} else {
			log.Printf("Recovery code written to data directory — read and delete the .recovery-code file immediately")
		}
	}

	// Run startup integrity checks concurrently. Each operates on independent
	// data sets: orphan cleanup shreds dirs NOT in DB, incomplete upload cleanup
	// shreds dirs IN DB with missing files, size backfill only reads files.
	// Query media summaries once and share across goroutines (read-only).
	summaries, err := db.ListAllMediaSummaries(database)
	if err != nil {
		log.Printf("Warning: startup integrity checks skipped — failed to list media: %v", err)
		summaries = nil
	}

	var startupWg sync.WaitGroup
	startupWg.Add(3)

	// 1. Clean up orphaned data directories not referenced in DB.
	go func() {
		defer startupWg.Done()
		if summaries == nil {
			return
		}
		validPaths := make(map[string]bool, len(summaries))
		for _, s := range summaries {
			validPaths[s.UserID+"/"+s.ID] = true
		}
		if removed, err := store.CleanupOrphans(validPaths); err != nil {
			log.Printf("Warning: orphan cleanup failed: %v", err)
		} else if removed > 0 {
			log.Printf("Cleaned up %d orphaned media directories", removed)
		}
	}()

	// 2. Clean up incomplete uploads — DB records whose chunk files are missing.
	// Uses a worker pool for parallel stat() checks.
	go func() {
		defer startupWg.Done()
		if summaries == nil {
			return
		}

		type incompleteItem struct {
			UserID string
			ID     string
		}
		var incompleteMu sync.Mutex
		var incomplete []incompleteItem

		// Parallel completeness checks (stat-heavy)
		workers := runtime.NumCPU()
		if workers > 8 {
			workers = 8
		}
		work := make(chan db.MediaSummary, workers*2)
		var checkWg sync.WaitGroup
		for i := 0; i < workers; i++ {
			checkWg.Add(1)
			go func() {
				defer checkWg.Done()
				for s := range work {
					if !store.IsMediaComplete(s.UserID, s.ID, s.ChunkCount) {
						incompleteMu.Lock()
						incomplete = append(incomplete, incompleteItem{s.UserID, s.ID})
						incompleteMu.Unlock()
					}
				}
			}()
		}
		for _, s := range summaries {
			work <- s
		}
		close(work)
		checkWg.Wait()

		for _, item := range incomplete {
			store.RemoveMedia(item.UserID, item.ID)
			db.DeleteMediaByID(database, item.ID)
		}
		if len(incomplete) > 0 {
			log.Printf("Cleaned up %d incomplete uploads", len(incomplete))
		}
	}()

	// 3. Backfill size_bytes for uploads where the server crashed after writing
	// chunks but before updating the DB record with the actual size.
	go func() {
		defer startupWg.Done()
		zeroItems, err := db.ListMediaWithZeroSize(database)
		if err != nil {
			log.Printf("Warning: size_bytes backfill skipped — failed to list: %v", err)
			return
		}
		backfilled := 0
		const sizeQuantum = 256 * 1024
		for _, item := range zeroItems {
			if size := store.MediaChunkBytes(item.UserID, item.ID, item.ChunkCount); size > 0 {
				quantized := ((size + sizeQuantum - 1) / sizeQuantum) * sizeQuantum
				if err := db.UpdateMediaSize(database, item.ID, quantized); err == nil {
					backfilled++
				}
			}
		}
		if backfilled > 0 {
			log.Printf("Backfilled size_bytes for %d media records", backfilled)
		}
	}()

	startupWg.Wait()

	// Start session cleanup goroutine (removes expired sessions every minute)
	auth.Sessions.StartCleanup()

	var maxBytes int64 = 1 * 1024 * 1024 * 1024 // default: 1 GB per user
	if v := os.Getenv("MAX_STORAGE_GB"); v != "" {
		if gb, err := strconv.ParseFloat(v, 64); err == nil && gb > 0 {
			maxBytes = int64(gb * 1024 * 1024 * 1024)
		}
	} else if v := os.Getenv("MAX_STORAGE_CHUNKS"); v != "" {
		// Legacy: convert chunk count to bytes (1 MB per chunk estimate).
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxBytes = int64(n) * 1048576
		}
	}

	shredder := storage.NewShredder(store, 0) // workers default to NumCPU (capped at 8)

	srv := &server.Server{
		DB:                database,
		Storage:           store,
		Shredder:          shredder,
		WebFS:             webFS,
		Addr:              *addr,
		PersistSession:    os.Getenv("PERSIST_SESSION") != "false",
		AllowRegistration: os.Getenv("ALLOW_REGISTRATION") == "true", // default false
		TrustProxy:        os.Getenv("TRUST_PROXY") == "true",        // default false — only enable behind a reverse proxy
		MaxStorageBytes:   maxBytes,
	}

	// Graceful shutdown: drain in-flight requests, finish pending shreds, then close DB
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
		log.Println("Waiting for pending shred operations...")
		shredder.Shutdown()
	}()

	if err := srv.Run(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Shutdown complete")
}
