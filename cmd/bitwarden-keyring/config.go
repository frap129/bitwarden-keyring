package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/logging"
)

const (
	version = "0.6.0"
)

// validComponents defines the supported component names
var validComponents = map[string]bool{
	"secrets": true,
	"ssh":     true,
}

// Config holds all application configuration
type Config struct {
	BWPort                 int
	BWStartTimeout         time.Duration
	Debug                  bool
	DebugHTTP              bool
	NoctaliaEnabled        bool
	NoctaliaSocket         string
	NoctaliaTimeout        time.Duration
	AllowInsecurePrompts   bool
	SystemdAskPasswordPath string
	SessionStore           string
	SessionFile            string
	MaxPasswordRetries     int
	EnabledComponents      map[string]bool
	SSHSocketPath          string
	NoSSHEnvExport         bool
	Version                string
}

// SessionConfig returns a bitwarden.SessionConfig from the Config
func (c *Config) SessionConfig() bitwarden.SessionConfig {
	return bitwarden.SessionConfig{
		NoctaliaEnabled:        c.NoctaliaEnabled,
		NoctaliaSocket:         c.NoctaliaSocket,
		NoctaliaTimeout:        c.NoctaliaTimeout,
		AllowInsecurePrompts:   c.AllowInsecurePrompts,
		SystemdAskPasswordPath: c.SystemdAskPasswordPath,
		SessionStore:           c.SessionStore,
		SessionFile:            c.SessionFile,
		MaxPasswordRetries:     c.MaxPasswordRetries,
	}
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

// selectPort returns the port to use, handling deprecated flag and auto-selection
func selectPort(bwPortFlag, deprecatedPortFlag int) (int, error) {
	selectedPort := bwPortFlag

	// Handle deprecated --port flag
	if deprecatedPortFlag != 0 {
		logging.L.Warn("--port is deprecated, use --bw-port instead")
		if bwPortFlag == 0 {
			selectedPort = deprecatedPortFlag
		}
	}

	// Port auto-selection if not specified
	if selectedPort == 0 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, fmt.Errorf("failed to auto-select port: %w", err)
		}
		selectedPort = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		logging.L.Info("auto-selected port", "port", selectedPort)
	}

	return selectedPort, nil
}

// validateConfig validates the configuration values
func validateConfig(cfg *Config) error {
	// Validate systemd-ask-password-path if provided
	if cfg.SystemdAskPasswordPath != "" && !strings.HasPrefix(cfg.SystemdAskPasswordPath, "/") {
		return fmt.Errorf("--systemd-ask-password-path must be an absolute path, got: %s", cfg.SystemdAskPasswordPath)
	}

	// Validate session-store
	if cfg.SessionStore != "memory" && cfg.SessionStore != "file" {
		return fmt.Errorf("--session-store must be 'memory' or 'file', got: %s", cfg.SessionStore)
	}

	return nil
}

// ConfigFromArgs parses command-line arguments and returns a Config.
// It uses a flag.FlagSet instead of the global flag package for isolated parsing.
func ConfigFromArgs(args []string) (Config, error) {
	fs := flag.NewFlagSet("bitwarden-keyring", flag.ContinueOnError)

	// Define all flags on the FlagSet
	var (
		fPort                   = fs.Int("port", 0, "DEPRECATED: use --bw-port instead")
		fBwPort                 = fs.Int("bw-port", 0, "Port for Bitwarden serve API (0 = auto-select)")
		fBwStartTimeout         = fs.Duration("bw-start-timeout", 10*time.Second, "Timeout for bw serve to start and become ready")
		fDebug                  = fs.Bool("debug", false, "Enable debug logging")
		fDebugHTTP              = fs.Bool("debug-http", false, "Enable HTTP body logging for errors (requires --debug to be effective)")
		fNoctaliaFlag           = fs.Bool("noctalia", false, "Enable Noctalia UI integration for password prompts")
		fNoctaliaSocket         = fs.String("noctalia-socket", "", "Custom Noctalia socket path (default: $XDG_RUNTIME_DIR/noctalia-keyring.sock)")
		fNoctaliaTimeout        = fs.Duration("noctalia-timeout", 120*time.Second, "Noctalia prompt timeout")
		fComponents             = fs.String("components", "", "Components to enable (comma-separated): secrets,ssh. Default: all")
		fSshSocket              = fs.String("ssh-socket", "", "SSH agent socket path (default: $XDG_RUNTIME_DIR/bitwarden-keyring/ssh.sock)")
		fNoSSHEnvExport         = fs.Bool("no-ssh-env-export", false, "Disable automatic SSH_AUTH_SOCK export to D-Bus/systemd environment")
		fAllowInsecurePrompts   = fs.Bool("allow-insecure-prompts", false, "Allow insecure password prompt methods like dmenu")
		fSystemdAskPasswordPath = fs.String("systemd-ask-password-path", "", "Absolute path to systemd-ask-password binary")
		fSessionStore           = fs.String("session-store", "memory", "Session storage mode: 'memory' or 'file' (default: memory)")
		fSessionFile            = fs.String("session-file", "", "Custom session file path (default: $XDG_CONFIG_HOME/bitwarden-keyring/session)")
		fMaxPasswordRetries     = fs.Int("max-password-retries", 3, "Maximum password retry attempts (default: 3)")
	)

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return Config{}, err
		}
		return Config{}, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Select port (handles deprecated flag and auto-selection)
	selectedPort, err := selectPort(*fBwPort, *fPort)
	if err != nil {
		return Config{}, err
	}

	// Parse and validate components
	enabledComponents, err := parseComponents(*fComponents)
	if err != nil {
		return Config{}, fmt.Errorf("invalid --components flag: %w", err)
	}

	// Check for environment variable override for Noctalia
	noctaliaEnabled := *fNoctaliaFlag
	if os.Getenv("BITWARDEN_KEYRING_NOCTALIA") == "1" {
		noctaliaEnabled = true
	}

	cfg := Config{
		BWPort:                 selectedPort,
		BWStartTimeout:         *fBwStartTimeout,
		Debug:                  *fDebug,
		DebugHTTP:              *fDebugHTTP,
		NoctaliaEnabled:        noctaliaEnabled,
		NoctaliaSocket:         *fNoctaliaSocket,
		NoctaliaTimeout:        *fNoctaliaTimeout,
		AllowInsecurePrompts:   *fAllowInsecurePrompts,
		SystemdAskPasswordPath: *fSystemdAskPasswordPath,
		SessionStore:           *fSessionStore,
		SessionFile:            *fSessionFile,
		MaxPasswordRetries:     *fMaxPasswordRetries,
		EnabledComponents:      enabledComponents,
		SSHSocketPath:          *fSshSocket,
		NoSSHEnvExport:         *fNoSSHEnvExport,
		Version:                version,
	}

	// Validate the configuration
	if err := validateConfig(&cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// ConfigFromFlags parses command-line flags and returns a Config.
// It is a wrapper around ConfigFromArgs using os.Args[1:].
func ConfigFromFlags() (Config, error) {
	return ConfigFromArgs(os.Args[1:])
}

// EnabledComponentsList returns a sorted list of enabled component names
func (c *Config) EnabledComponentsList() []string {
	var componentList []string
	for comp := range c.EnabledComponents {
		componentList = append(componentList, comp)
	}
	sort.Strings(componentList)
	return componentList
}
