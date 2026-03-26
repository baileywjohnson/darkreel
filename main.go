package main

import (
	"embed"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	srv := &server.Server{
		DB:      database,
		Storage: store,
		WebFS:   webFS,
		Addr:    *addr,
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
