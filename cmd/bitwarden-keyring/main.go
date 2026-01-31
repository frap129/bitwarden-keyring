package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	secretdbus "github.com/joe/bitwarden-keyring/internal/dbus"
	"github.com/joe/bitwarden-keyring/internal/ssh"
)

var (
	port            = flag.Int("port", 0, "DEPRECATED: use --bw-port instead")
	bwPort          = flag.Int("bw-port", 0, "Port for Bitwarden serve API (0 = auto-select)")
	bwStartTimeout  = flag.Duration("bw-start-timeout", 10*time.Second, "Timeout for bw serve to start and become ready")
	debug           = flag.Bool("debug", false, "Enable debug logging")
	debugHTTP       = flag.Bool("debug-http", false, "Enable HTTP body logging for errors (requires --debug to be effective)")
	noctaliaFlag    = flag.Bool("noctalia", false, "Enable Noctalia UI integration for password prompts")
	noctaliaSocket  = flag.String("noctalia-socket", "", "Custom Noctalia socket path (default: $XDG_RUNTIME_DIR/noctalia-polkit-agent.sock)")
	noctaliaTimeout = flag.Duration("noctalia-timeout", 120*time.Second, "Noctalia prompt timeout")
	components      = flag.String("components", "", "Components to enable (comma-separated): secrets,ssh. Default: all")
	sshSocket       = flag.String("ssh-socket", "", "SSH agent socket path (default: $XDG_RUNTIME_DIR/bitwarden-keyring/ssh.sock)")
	version         = "0.4.0"
)

// validComponents defines the supported component names
var validComponents = map[string]bool{
	"secrets": true,
	"ssh":     true,
}

// validComponentsList returns a sorted, comma-separated list of valid component names
func validComponentsList() string {
	names := make([]string, 0, len(validComponents))
	for c := range validComponents {
		names = append(names, c)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// parseComponents parses the component flag and returns a map of enabled components.
// If componentStr is empty, all components are enabled.
func parseComponents(componentStr string) (map[string]bool, error) {
	enabled := make(map[string]bool)

	// If empty, enable all components
	if componentStr == "" {
		for c := range validComponents {
			enabled[c] = true
		}
		return enabled, nil
	}

	// Parse comma-separated list
	for _, c := range strings.Split(componentStr, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !validComponents[c] {
			return nil, fmt.Errorf("unknown component: %s (valid: %s)", c, validComponentsList())
		}
		enabled[c] = true
	}

	if len(enabled) == 0 {
		return nil, fmt.Errorf("no components specified")
	}

	return enabled, nil
}

func main() {
	flag.Parse()

	if *debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Handle deprecated --port flag
	selectedPort := *bwPort
	if *port != 0 {
		log.Printf("Warning: --port is deprecated, use --bw-port instead")
		if *bwPort == 0 {
			selectedPort = *port
		}
	}

	// Port auto-selection if not specified
	if selectedPort == 0 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Fatalf("Failed to auto-select port: %v", err)
		}
		selectedPort = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		log.Printf("Auto-selected port: %d", selectedPort)
	}

	// Parse and validate components
	enabledComponents, err := parseComponents(*components)
	if err != nil {
		log.Fatalf("Invalid --components flag: %v", err)
	}

	// Log enabled components
	var componentList []string
	for c := range enabledComponents {
		componentList = append(componentList, c)
	}
	sort.Strings(componentList)

	log.Printf("bitwarden-keyring %s starting...", version)
	log.Printf("Enabled components: %s", strings.Join(componentList, ", "))

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
	bwClient := bitwarden.NewClientWithConfig(selectedPort, sessionCfg)

	// Enable HTTP body logging if both --debug and --debug-http are set
	if *debug && *debugHTTP {
		bwClient.SetDebug(true)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bw serve with timeout - FAIL-CLOSED
	log.Printf("Starting bw serve on port %d...", selectedPort)
	startCtx, startCancel := context.WithTimeout(ctx, *bwStartTimeout)
	defer startCancel()

	if err := bwClient.StartServe(startCtx, selectedPort); err != nil {
		log.Fatalf("Failed to start and verify bw serve: %v", err)
	}

	// Verify backend is healthy before continuing
	if err := bwClient.ServeHealthy(); err != nil {
		log.Fatalf("Backend not healthy after start: %v", err)
	}

	log.Printf("Bitwarden backend ready")

	// Connect to session D-Bus (needed for secrets component)
	var conn *dbus.Conn
	if enabledComponents["secrets"] {
		conn, err = dbus.ConnectSessionBus()
		if err != nil {
			log.Fatalf("Failed to connect to session bus: %v", err)
		}
		defer conn.Close()

		log.Printf("Connected to session D-Bus")

		// Create and export the service
		service, err := secretdbus.NewService(conn, bwClient)
		if err != nil {
			log.Fatalf("Failed to create service: %v", err)
		}

		if err := service.Export(); err != nil {
			log.Fatalf("Failed to export service: %v", err)
		}

		log.Printf("Secret Service exported at %s", secretdbus.BusName)
		log.Printf("Ready to serve secrets from Bitwarden vault")
	}

	// Start SSH agent if enabled
	var sshServer *ssh.Server
	if enabledComponents["ssh"] {
		socketPath := *sshSocket
		if socketPath == "" {
			socketPath = ssh.DefaultSocketPath()
		}

		sshServer = ssh.NewServer(socketPath, bwClient)
		sshServer.SetDebug(*debug)

		if err := sshServer.Start(ctx); err != nil {
			log.Fatalf("Failed to start SSH agent: %v", err)
		}
		log.Printf("SSH agent listening on %s", socketPath)
		log.Printf("Set SSH_AUTH_SOCK=%s to use", socketPath)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	fmt.Println()
	log.Printf("Shutting down...")

	// Stop SSH agent
	if sshServer != nil {
		if err := sshServer.Stop(); err != nil {
			log.Printf("Warning: Failed to stop SSH agent: %v", err)
		}
	}

	// Stop bw serve
	if err := bwClient.Stop(); err != nil {
		log.Printf("Warning: Failed to stop bw serve: %v", err)
	}

	log.Printf("Goodbye!")
}
