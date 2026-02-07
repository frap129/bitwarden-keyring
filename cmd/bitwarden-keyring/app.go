package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	secretdbus "github.com/joe/bitwarden-keyring/internal/dbus"
	"github.com/joe/bitwarden-keyring/internal/logging"
	"github.com/joe/bitwarden-keyring/internal/ssh"
)

// App coordinates the application components
type App struct {
	config    Config
	bwClient  *bitwarden.Client
	conn      *dbus.Conn
	service   *secretdbus.Service
	sshServer *ssh.Server
}

// NewApp creates a new App with the given configuration
func NewApp(cfg Config) *App {
	return &App{
		config: cfg,
	}
}

// Start initializes and starts all enabled components.
// Uses fail-closed approach: returns error if any component fails.
func (a *App) Start(ctx context.Context) error {
	// Check if Bitwarden CLI is available
	if _, err := exec.LookPath("bw"); err != nil {
		return fmt.Errorf("Bitwarden CLI (bw) not found in PATH. Please install it: https://bitwarden.com/help/cli/")
	}

	// Log startup info
	logging.L.Info("bitwarden-keyring starting", "version", a.config.Version)
	logging.L.Info("enabled components", "components", strings.Join(a.config.EnabledComponentsList(), ", "))

	if a.config.NoctaliaEnabled {
		logging.L.Info("noctalia UI integration enabled")
	}

	// Start Bitwarden backend
	if err := a.startBitwardenBackend(ctx); err != nil {
		return err
	}

	// Start Secret Service if enabled
	if a.config.EnabledComponents["secrets"] {
		if err := a.startSecretService(); err != nil {
			return err
		}
	}

	// Start SSH agent if enabled
	if a.config.EnabledComponents["ssh"] {
		if err := a.startSSHAgent(ctx); err != nil {
			return err
		}
	}

	return nil
}

// startBitwardenBackend starts bw serve and waits for it to be ready
func (a *App) startBitwardenBackend(ctx context.Context) error {
	// Create Bitwarden client with session config
	a.bwClient = bitwarden.NewClientWithConfig(a.config.BWPort, a.config.SessionConfig())

	// Enable HTTP body logging if both --debug and --debug-http are set
	if a.config.Debug && a.config.DebugHTTP {
		a.bwClient.SetDebug(true)
	}

	// Start bw serve with timeout - FAIL-CLOSED
	logging.L.Info("starting bw serve", "port", a.config.BWPort)
	startCtx, startCancel := context.WithTimeout(ctx, a.config.BWStartTimeout)
	defer startCancel()

	if err := a.bwClient.StartServe(startCtx, a.config.BWPort); err != nil {
		return fmt.Errorf("failed to start and verify bw serve: %w", err)
	}

	// Verify backend is healthy before continuing
	if err := a.bwClient.ServeHealthy(); err != nil {
		return fmt.Errorf("backend not healthy after start: %w", err)
	}

	logging.L.Info("bitwarden backend ready")
	return nil
}

// startSecretService connects to D-Bus and exports the Secret Service
func (a *App) startSecretService() error {
	var err error
	a.conn, err = dbus.ConnectSessionBus()
	if err != nil {
		return fmt.Errorf("failed to connect to session bus: %w", err)
	}

	logging.L.Info("connected to session D-Bus")

	// Create and export the service
	a.service, err = secretdbus.NewService(a.conn, a.bwClient)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	if err := a.service.Export(); err != nil {
		return fmt.Errorf("failed to export service: %w", err)
	}

	logging.L.Info("secret service exported", "busname", secretdbus.BusName)
	logging.L.Info("ready to serve secrets from bitwarden vault")
	return nil
}

// startSSHAgent starts the SSH agent server
func (a *App) startSSHAgent(ctx context.Context) error {
	socketPath := a.config.SSHSocketPath
	if socketPath == "" {
		socketPath = ssh.DefaultSocketPath()
	}

	a.sshServer = ssh.NewServer(socketPath, a.bwClient)
	a.sshServer.SetDebug(a.config.Debug)

	if err := a.sshServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start SSH agent: %w", err)
	}

	logging.L.Info("SSH agent listening", "socket", socketPath)

	if !a.config.NoSSHEnvExport {
		if err := exportSSHAuthSock(socketPath); err != nil {
			return fmt.Errorf("failed to export SSH_AUTH_SOCK: %w", err)
		}
		logging.L.Info("exported SSH_AUTH_SOCK to D-Bus activation environment")
	} else {
		logging.L.Info("SSH_AUTH_SOCK configured", "socket", socketPath)
	}
	return nil
}

// exportSSHAuthSock uses dbus-update-activation-environment to propagate
// SSH_AUTH_SOCK to the systemd and D-Bus user session so that applications
// launched from desktop environments or systemd user services can discover
// the agent socket. It is a no-op when systemd is not running or the
// command is not installed.
func exportSSHAuthSock(socketPath string) error {
	if !isSystemdUserRunning() {
		return nil
	}

	cmd := "dbus-update-activation-environment"
	if _, err := exec.LookPath(cmd); err != nil {
		return nil
	}

	arg := "SSH_AUTH_SOCK=" + socketPath
	if out, err := exec.Command(cmd, arg).CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", cmd, err, out)
	}
	return nil
}

// isSystemdUserRunning checks whether a systemd user session is active
// by testing for the existence of the systemd user manager's private socket.
func isSystemdUserRunning() bool {
	xdgRuntime := os.Getenv("XDG_RUNTIME_DIR")
	if xdgRuntime == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(xdgRuntime, "systemd", "private"))
	return err == nil
}

// Stop gracefully shuts down all components in reverse order
func (a *App) Stop() error {
	var errs []string

	// Stop SSH agent
	if a.sshServer != nil {
		if err := a.sshServer.Stop(); err != nil {
			errs = append(errs, fmt.Sprintf("SSH agent: %v", err))
		}
	}

	// Close D-Bus connection
	if a.conn != nil {
		if err := a.conn.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("D-Bus: %v", err))
		}
	}

	// Stop bw serve
	if a.bwClient != nil {
		if err := a.bwClient.Stop(); err != nil {
			errs = append(errs, fmt.Sprintf("bw serve: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
