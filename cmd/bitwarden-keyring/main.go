package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// run contains the main application logic and is testable.
// It takes command-line arguments and returns an error if execution fails.
func run(args []string) error {
	cfg, err := ConfigFromArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // help already printed by FlagSet
		}
		return fmt.Errorf("configuration error: %w", err)
	}

	if cfg.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	app := NewApp(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Start(ctx); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	<-sigChan
	fmt.Println()
	log.Printf("Shutting down...")

	if err := app.Stop(); err != nil {
		log.Printf("Warning during shutdown: %v", err)
	}

	log.Printf("Goodbye!")
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("%v", err)
	}
}
