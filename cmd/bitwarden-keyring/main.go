package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/joe/bitwarden-keyring/internal/logging"
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

	logging.Setup(cfg.Debug)

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
	logging.L.Info("shutting down")

	if err := app.Stop(); err != nil {
		logging.L.Warn("warning during shutdown", "error", err)
	}

	logging.L.Info("goodbye")
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		logging.L.Error("fatal error", "error", err)
		os.Exit(1)
	}
}
