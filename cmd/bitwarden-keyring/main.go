package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	cfg, err := ConfigFromFlags()
	if err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	if cfg.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	app := NewApp(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Start(ctx); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	fmt.Println()
	log.Printf("Shutting down...")

	if err := app.Stop(); err != nil {
		log.Printf("Warning during shutdown: %v", err)
	}

	log.Printf("Goodbye!")
}
