package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	secretdbus "github.com/joe/bitwarden-keyring/internal/dbus"
)

var (
	port            = flag.Int("port", 8087, "Port for Bitwarden serve API")
	debug           = flag.Bool("debug", false, "Enable debug logging")
	noctaliaFlag    = flag.Bool("noctalia", false, "Enable Noctalia UI integration for password prompts")
	noctaliaSocket  = flag.String("noctalia-socket", "", "Custom Noctalia socket path (default: $XDG_RUNTIME_DIR/noctalia-polkit-agent.sock)")
	noctaliaTimeout = flag.Duration("noctalia-timeout", 120*time.Second, "Noctalia prompt timeout")
	version         = "0.2.0"
)

func main() {
	flag.Parse()

	if *debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	log.Printf("bitwarden-keyring %s starting...", version)

	// Check if Bitwarden CLI is available
	if _, err := exec.LookPath("bw"); err != nil {
		log.Fatalf("Bitwarden CLI (bw) not found in PATH. Please install it: https://bitwarden.com/help/cli/")
	}

	// Check for environment variable override for Noctalia
	noctaliaEnabled := *noctaliaFlag
	if os.Getenv("BITWARDEN_KEYRING_NOCTALIA") == "1" {
		noctaliaEnabled = true
	}

	// Create session config
	sessionCfg := bitwarden.SessionConfig{
		NoctaliaEnabled: noctaliaEnabled,
		NoctaliaSocket:  *noctaliaSocket,
		NoctaliaTimeout: *noctaliaTimeout,
	}

	if noctaliaEnabled {
		log.Printf("Noctalia UI integration enabled")
	}

	// Create Bitwarden client with session config
	bwClient := bitwarden.NewClientWithConfig(*port, sessionCfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bw serve
	log.Printf("Starting bw serve on port %d...", *port)
	if err := bwClient.StartServe(ctx, *port); err != nil {
		log.Printf("Warning: Failed to start bw serve: %v", err)
		log.Printf("Make sure 'bw serve --port %d' is running or BW_SESSION is set", *port)
	}

	// Connect to session D-Bus
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		log.Fatalf("Failed to connect to session bus: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to session D-Bus")

	// Create and export the service
	service := secretdbus.NewUnifiedService(conn, bwClient)

	if err := service.Export(); err != nil {
		log.Fatalf("Failed to export service: %v", err)
	}

	log.Printf("Secret Service exported at %s", secretdbus.BusName)
	log.Printf("Ready to serve secrets from Bitwarden vault")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	fmt.Println()
	log.Printf("Shutting down...")

	// Stop bw serve
	if err := bwClient.Stop(); err != nil {
		log.Printf("Warning: Failed to stop bw serve: %v", err)
	}

	log.Printf("Goodbye!")
}
