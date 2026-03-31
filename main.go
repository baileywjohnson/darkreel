package main

import (
	"embed"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

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
		if err := auth.BootstrapAdmin(database, adminUser, adminPass); err != nil {
			log.Fatalf("Failed to create admin user: %v", err)
		}
		log.Printf("Admin user %q created", adminUser)
	}

	srv := &server.Server{
		DB:                database,
		Storage:           store,
		WebFS:             webFS,
		Addr:              *addr,
		PersistSession:    os.Getenv("PERSIST_SESSION") == "true",
		AllowRegistration: os.Getenv("ALLOW_REGISTRATION") == "true", // default false
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		database.Close()
		os.Exit(0)
	}()

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
