package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	// Default to loopback only — Darkreel does not terminate TLS and must run
	// behind a reverse proxy (see README). A fresh install that skips the proxy
	// step should fail closed instead of exposing JWT bearer tokens in cleartext.
	// Override with `-addr 0.0.0.0:8080` if you genuinely need a public bind.
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
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

		// Emit the recovery code to stderr AND to a short-lived file.
		//
		// Stderr: the operator is watching the bootstrap log, so they see
		// the code immediately. In a systemd deployment this also lands
		// in journald, which is root-only and scoped to the service.
		//
		// File: lets an automated setup script read the code without
		// parsing log output. The file is chmod 0600 and auto-deleted
		// after the grace window below — previously it persisted forever,
		// so any backup/snapshot/misconfigured share leaked a permanent
		// admin recovery primitive (which defeats zero-knowledge for the
		// admin account). Auto-delete closes that window.
		fmt.Fprintf(os.Stderr, "\n========================================\n")
		fmt.Fprintf(os.Stderr, "  ADMIN RECOVERY CODE — save this now!\n")
		fmt.Fprintf(os.Stderr, "  %s\n", recoveryCode)
		fmt.Fprintf(os.Stderr, "========================================\n\n")

		rcPath := filepath.Join(*dataDir, ".recovery-code")
		const recoveryCodeTTL = 5 * time.Minute
		if err := os.WriteFile(rcPath, []byte(recoveryCode), 0600); err != nil {
			log.Printf("Recovery code NOT written to disk (%v) — save the value printed above; it will not be shown again.", err)
		} else {
			log.Printf("Recovery code also written to %s — will be deleted automatically in %s.", rcPath, recoveryCodeTTL)
			go func() {
				time.Sleep(recoveryCodeTTL)
				if err := os.Remove(rcPath); err != nil && !os.IsNotExist(err) {
					log.Printf("Warning: failed to auto-delete recovery-code file %s: %v", rcPath, err)
				}
			}()
		}
	} else {
		// Scrub a stale .recovery-code file left behind by an older build
		// (before auto-delete was added). If someone managed the file
		// already, this is a no-op; if they forgot, we clean up after
		// them on next restart.
		rcPath := filepath.Join(*dataDir, ".recovery-code")
		if err := os.Remove(rcPath); err == nil {
			log.Printf("Removed stale .recovery-code file left by a previous bootstrap")
		}
	}

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

	// Run startup integrity checks concurrently. Each operates on independent
	// data sets: orphan cleanup shreds dirs NOT in DB, incomplete upload cleanup
	// shreds dirs IN DB with missing files, size backfill only reads files.
	// Query media summaries once and share across goroutines (read-only).
	// listOK distinguishes "query failed" from "no media rows": an empty
	// table is exactly when orphaned files from deleted media must still be
	// cleaned up.
	summaries, err := db.ListAllMediaSummaries(database)
	listOK := err == nil
	if !listOK {
		log.Printf("Warning: startup integrity checks skipped — failed to list media: %v", err)
	}

	var startupWg sync.WaitGroup
	startupWg.Add(3)

	// 1. Clean up orphaned data directories not referenced in DB.
	go func() {
		defer startupWg.Done()
		if !listOK {
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
		if !listOK {
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

	// 3. Finish uploads where the server stopped after writing every chunk
	// but before the final quota-checked size update. Completion is defined
	// by passing that quota check, so apply it here too; otherwise an
	// upload that stalled before its closing boundary could land past quota
	// on the next restart.
	go func() {
		defer startupWg.Done()
		zeroItems, err := db.ListMediaWithZeroSize(database)
		if err != nil {
			log.Printf("Warning: size_bytes backfill skipped — failed to list: %v", err)
			return
		}
		backfilled, rejected := 0, 0
		for _, item := range zeroItems {
			size := store.MediaDiskBytes(item.UserID, item.ID, item.ChunkCount)
			if size <= 0 {
				continue // incomplete — handled by check 2
			}
			qi, err := db.GetQuotaInfo(database, item.UserID)
			if err != nil {
				continue
			}
			ok, err := db.UpdateMediaSizeWithQuotaCheck(database, item.ID, item.UserID, size, db.EffectiveQuota(qi, maxBytes))
			if err != nil {
				continue
			}
			if ok {
				backfilled++
				continue
			}
			db.DeleteMediaByID(database, item.ID)
			store.RemoveMedia(item.UserID, item.ID)
			rejected++
		}
		if backfilled > 0 {
			log.Printf("Backfilled size_bytes for %d media records", backfilled)
		}
		if rejected > 0 {
			log.Printf("Removed %d interrupted uploads that exceeded quota", rejected)
		}
	}()

	startupWg.Wait()

	// One-time migration: quota used to be charged on ciphertext bytes, which
	// ignored the padding every chunk and thumbnail occupies on disk.
	// Recompute every completed item's charge from its real on-disk size.
	// Users may end up over quota; they simply can't upload more until they
	// delete something.
	if v, _ := db.GetSetting(database, "quota_accounting"); v != "disk-v1" && listOK {
		updated := 0
		for _, s := range summaries {
			if size := store.MediaDiskBytes(s.UserID, s.ID, s.ChunkCount); size > 0 {
				if err := db.UpdateMediaSizeIfSet(database, s.ID, size); err == nil {
					updated++
				}
			}
		}
		if err := db.SetSetting(database, "quota_accounting", "disk-v1"); err != nil {
			log.Printf("Warning: failed to record quota accounting migration: %v", err)
		}
		log.Printf("Recomputed storage usage from on-disk size for %d media records", updated)
	}

	// Start session cleanup goroutine (removes expired sessions every minute)
	auth.Sessions.StartCleanup()
	db.StartWALMaintenance(database, 5*time.Minute)
	// Delegation authorization codes are short-lived (2 min); prune expired
	// entries periodically so the codes table stays small under consent churn.
	auth.StartDelegationCodeCleanup(database)

	shredder := storage.NewShredder(store, 0) // workers default to NumCPU (capped at 8)

	// Parse TRUST_PROXY_CIDR (comma-separated) if set. Invalid entries are
	// skipped with a warning rather than fatal — the operator still gets a
	// working server; they just fall back to the legacy "trust any upstream"
	// behavior for the unparsable entry.
	var trustCIDRs []*net.IPNet
	if raw := os.Getenv("TRUST_PROXY_CIDR"); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			_, cidr, err := net.ParseCIDR(p)
			if err != nil {
				log.Printf("Warning: TRUST_PROXY_CIDR entry %q is not a valid CIDR — skipping", p)
				continue
			}
			trustCIDRs = append(trustCIDRs, cidr)
		}
	}

	srv := &server.Server{
		DB:                database,
		Storage:           store,
		Shredder:          shredder,
		WebFS:             webFS,
		Addr:              *addr,
		PersistSession:    os.Getenv("PERSIST_SESSION") != "false",
		AllowRegistration: os.Getenv("ALLOW_REGISTRATION") == "true", // default false
		TrustProxy:        os.Getenv("TRUST_PROXY") == "true",        // default false — only enable behind a reverse proxy
		TrustProxyCIDRs:   trustCIDRs,
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
