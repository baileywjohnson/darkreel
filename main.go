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

		// Write recovery code to a file so it isn't lost if stderr is missed
		rcPath := filepath.Join(*dataDir, "RECOVERY_CODE")
		if err := os.WriteFile(rcPath, []byte(recoveryCode+"\n"), 0600); err != nil {
			log.Printf("Warning: could not write recovery code file: %v", err)
		} else {
			fmt.Fprintf(os.Stderr, "  Recovery code also saved to: %s\n", rcPath)
			fmt.Fprintf(os.Stderr, "  DELETE THIS FILE after saving the code elsewhere.\n\n")
		}
	}

	// Clean up orphaned data directories not referenced in DB
	validPaths := make(map[string]bool)
	userIDs, _ := db.ListUserIDs(database)
	for _, uid := range userIDs {
		mediaIDs, _ := db.ListMediaIDsByUser(database, uid)
		for _, mid := range mediaIDs {
			validPaths[uid+"/"+mid] = true
		}
	}
	if removed, err := store.CleanupOrphans(validPaths); err != nil {
		log.Printf("Warning: orphan cleanup failed: %v", err)
	} else if removed > 0 {
		log.Printf("Cleaned up %d orphaned media directories", removed)
	}

	// Start session cleanup goroutine (removes expired sessions every minute)
	auth.Sessions.StartCleanup()

	srv := &server.Server{
		DB:                database,
		Storage:           store,
		WebFS:             webFS,
		Addr:              *addr,
		PersistSession:    os.Getenv("PERSIST_SESSION") != "false",
		AllowRegistration: os.Getenv("ALLOW_REGISTRATION") == "true", // default false
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
