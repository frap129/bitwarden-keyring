package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joe/bitwarden-keyring/internal/noctalia"
)

// ErrUserCancelled indicates the user cancelled the password prompt
var ErrUserCancelled = errors.New("user cancelled password prompt")

// ErrNoSecurePromptAvailable indicates no secure password prompt methods are available
var ErrNoSecurePromptAvailable = errors.New("no secure password prompt available (only dmenu found, use --allow-insecure-prompts to enable)")

// isUserCancelled checks if the error indicates user cancelled the prompt.
// CLI tools like zenity, kdialog, rofi exit with code 1 when cancelled.
// Zenity also exits with code 5 on timeout, which we treat as cancellation.
func isUserCancelled(err error) bool {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		return code == 1 || code == 5 // 1=cancel, 5=timeout (zenity)
	}
	return false
}

// commandExists checks if a command is available in PATH
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// SessionConfig configures the SessionManager behavior
type SessionConfig struct {
	// NoctaliaEnabled enables Noctalia UI integration for password prompts
	NoctaliaEnabled bool
	// NoctaliaSocket is an optional custom socket path for Noctalia
	NoctaliaSocket string
	// NoctaliaTimeout is the timeout for Noctalia password prompts
	NoctaliaTimeout time.Duration
	// AllowInsecurePrompts allows using insecure prompt methods like dmenu (default: false)
	AllowInsecurePrompts bool
	// SystemdAskPasswordPath is an optional absolute path to systemd-ask-password
	SystemdAskPasswordPath string
	// SessionStore specifies where to store the session: "memory" or "file" (default: "memory")
	SessionStore string
	// SessionFile is the path to the session file (used when SessionStore is "file")
	SessionFile string
}

// DefaultSessionConfig returns a SessionConfig with default values
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		NoctaliaEnabled:        false,
		NoctaliaSocket:         "",
		NoctaliaTimeout:        noctalia.DefaultTimeout,
		AllowInsecurePrompts:   false,
		SystemdAskPasswordPath: "",
		SessionStore:           "memory",
		SessionFile:            "",
	}
}

// SessionManager handles Bitwarden session key management
type SessionManager struct {
	sessionKey             string
	mu                     sync.RWMutex
	noctaliaClient         *noctalia.Client
	noctaliaEnabled        bool
	allowInsecurePrompts   bool
	systemdAskPasswordPath string
	pathDiscoveryWarned    bool
	sessionStore           string
	sessionFile            string
}

// NewSessionManager creates a new session manager with default config
func NewSessionManager() *SessionManager {
	return NewSessionManagerWithConfig(DefaultSessionConfig())
}

// NewSessionManagerWithConfig creates a new session manager with the given config
func NewSessionManagerWithConfig(cfg SessionConfig) *SessionManager {
	sm := &SessionManager{
		noctaliaEnabled:        cfg.NoctaliaEnabled,
		allowInsecurePrompts:   cfg.AllowInsecurePrompts,
		systemdAskPasswordPath: cfg.SystemdAskPasswordPath,
		sessionStore:           cfg.SessionStore,
		sessionFile:            cfg.SessionFile,
	}

	// Default to "memory" if not specified
	if sm.sessionStore == "" {
		sm.sessionStore = "memory"
	}

	// Initialize Noctalia client if enabled
	if cfg.NoctaliaEnabled {
		var opts []noctalia.Option
		if cfg.NoctaliaSocket != "" {
			opts = append(opts, noctalia.WithSocketPath(cfg.NoctaliaSocket))
		}
		if cfg.NoctaliaTimeout > 0 {
			opts = append(opts, noctalia.WithTimeout(cfg.NoctaliaTimeout))
		}
		sm.noctaliaClient = noctalia.NewClient(opts...)
	}

	// Try to load session from environment or file
	sm.loadSession()
	return sm
}

// GetSession returns the current session key
func (sm *SessionManager) GetSession() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessionKey
}

// SetSession stores the session key
func (sm *SessionManager) SetSession(key string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessionKey = key
	// Only persist to file if SessionStore is "file"
	if sm.sessionStore == "file" {
		sm.saveSessionToFile(key)
	}
}

// ClearSession clears the stored session key
func (sm *SessionManager) ClearSession() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessionKey = ""
	// Only delete file if SessionStore is "file"
	if sm.sessionStore == "file" {
		sm.deleteSessionFile()
	}
}

// HasSession returns whether a session key is available
func (sm *SessionManager) HasSession() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessionKey != ""
}

// loadSession attempts to load session from environment or file
func (sm *SessionManager) loadSession() {
	// First check environment variable
	if envSession := os.Getenv("BW_SESSION"); envSession != "" {
		sm.sessionKey = envSession
		return
	}

	// Only try to load from file if SessionStore is "file"
	if sm.sessionStore != "file" {
		return
	}

	// Try to load from session file
	sessionFile := sm.getSessionFilePath()

	// Reject symlinks for security
	fileInfo, err := os.Lstat(sessionFile)
	if err != nil {
		return // File doesn't exist or can't be accessed
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		log.Printf("Warning: Session file is a symlink, rejecting: %s", sessionFile)
		return
	}

	data, err := os.ReadFile(sessionFile)
	if err == nil {
		sm.sessionKey = strings.TrimSpace(string(data))
	}
}

// getSessionFilePath returns the path to the session file
func (sm *SessionManager) getSessionFilePath() string {
	// Use configured path if provided
	if sm.sessionFile != "" {
		return sm.sessionFile
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.Getenv("HOME")
	}
	return filepath.Join(configDir, "bitwarden-keyring", "session")
}

// saveSessionToFile persists the session key to a file
func (sm *SessionManager) saveSessionToFile(key string) {
	sessionFile := sm.getSessionFilePath()
	dir := filepath.Dir(sessionFile)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}

	// Check directory permissions for security
	dirInfo, err := os.Stat(dir)
	if err == nil {
		mode := dirInfo.Mode().Perm()
		// Warn if directory has group or world write permissions
		if mode&0022 != 0 {
			log.Printf("Warning: Session directory has insecure permissions (group/world-writable): %s (mode: %04o)", dir, mode)
		}
	}

	// Write session file with restricted permissions
	_ = os.WriteFile(sessionFile, []byte(key), 0600)
}

// deleteSessionFile removes the session file
func (sm *SessionManager) deleteSessionFile() {
	sessionFile := sm.getSessionFilePath()
	_ = os.Remove(sessionFile)
}

// promptMethod represents a password prompt method
type promptMethod struct {
	name string
}

// getPromptOrder returns the ordered list of prompt methods to try based on config
func getPromptOrder(cfg SessionConfig) []promptMethod {
	var prompts []promptMethod

	// 1. Noctalia (if enabled)
	if cfg.NoctaliaEnabled {
		prompts = append(prompts, promptMethod{name: "noctalia"})
	}

	// 2. systemd-ask-password
	prompts = append(prompts, promptMethod{name: "systemd-ask-password"})

	// 3. zenity
	prompts = append(prompts, promptMethod{name: "zenity"})

	// 4. kdialog
	prompts = append(prompts, promptMethod{name: "kdialog"})

	// 5. rofi
	prompts = append(prompts, promptMethod{name: "rofi"})

	// 6. dmenu (only if AllowInsecurePrompts)
	if cfg.AllowInsecurePrompts {
		prompts = append(prompts, promptMethod{name: "dmenu"})
	}

	return prompts
}

// PromptForPassword prompts the user for their master password using a GUI dialog
// It tries various GUI methods, falling back through the chain in order of security
func (sm *SessionManager) PromptForPassword() (string, error) {
	// Try Noctalia first if enabled
	if sm.noctaliaEnabled && sm.noctaliaClient != nil {
		password, err := sm.promptNoctalia()
		if err == nil {
			return password, nil
		}
		if errors.Is(err, noctalia.ErrCancelled) {
			// User explicitly cancelled - don't try fallback methods
			return "", ErrUserCancelled
		}
		if !errors.Is(err, noctalia.ErrSocketNotFound) && !errors.Is(err, noctalia.ErrConnectionFailed) {
			// Only log non-connection errors (connection errors just mean agent isn't running)
			log.Printf("Noctalia prompt failed: %v, trying fallback methods", err)
		}
	}

	// Log one-time warning about PATH discovery
	if !sm.pathDiscoveryWarned {
		log.Printf("DEBUG: Using PATH discovery for prompt tools - consider specifying absolute paths")
		sm.pathDiscoveryWarned = true
	}

	// Try systemd-ask-password (secure, works with Plymouth/console)
	if commandExists("systemd-ask-password") {
		password, err := sm.promptSystemd()
		if err == nil {
			return password, nil
		}
		if errors.Is(err, ErrUserCancelled) {
			return "", err
		}
	}

	// Try zenity (GNOME/GTK)
	if commandExists("zenity") {
		password, err := sm.promptZenity()
		if err == nil {
			return password, nil
		}
		if errors.Is(err, ErrUserCancelled) {
			return "", err
		}
	}

	// Try kdialog (KDE)
	if commandExists("kdialog") {
		password, err := sm.promptKDialog()
		if err == nil {
			return password, nil
		}
		if errors.Is(err, ErrUserCancelled) {
			return "", err
		}
	}

	// Try rofi (common on tiling WMs)
	if commandExists("rofi") {
		password, err := sm.promptRofi()
		if err == nil {
			return password, nil
		}
		if errors.Is(err, ErrUserCancelled) {
			return "", err
		}
	}

	// Try dmenu (insecure - only if explicitly allowed)
	if sm.allowInsecurePrompts && commandExists("dmenu") {
		password, err := sm.promptDmenu()
		if err == nil {
			return password, nil
		}
		if errors.Is(err, ErrUserCancelled) {
			return "", err
		}
	}

	// Check if only dmenu is available but not allowed
	if !sm.allowInsecurePrompts && commandExists("dmenu") {
		return "", ErrNoSecurePromptAvailable
	}

	return "", fmt.Errorf("no password prompt method available (install zenity, kdialog, rofi, or systemd-ask-password)")
}

// promptNoctalia uses the Noctalia agent for a password dialog
func (sm *SessionManager) promptNoctalia() (string, error) {
	if sm.noctaliaClient == nil {
		return "", noctalia.ErrSocketNotFound
	}

	if !sm.noctaliaClient.IsAvailable() {
		return "", noctalia.ErrSocketNotFound
	}

	ctx, cancel := context.WithTimeout(context.Background(), noctalia.DefaultTimeout)
	defer cancel()

	return sm.noctaliaClient.RequestPassword(ctx, "Bitwarden Keyring", "Enter your Bitwarden Master Password:")
}

// promptZenity uses zenity for a GTK password dialog
func (sm *SessionManager) promptZenity() (string, error) {
	cmd := exec.Command("zenity",
		"--password",
		"--title=Bitwarden Keyring",
		"--text=Enter your Bitwarden Master Password:",
		"--timeout=120",
	)
	output, err := cmd.Output()
	if err != nil {
		if isUserCancelled(err) {
			return "", ErrUserCancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// promptKDialog uses kdialog for a KDE password dialog
func (sm *SessionManager) promptKDialog() (string, error) {
	cmd := exec.Command("kdialog",
		"--password",
		"Enter your Bitwarden Master Password:",
		"--title", "Bitwarden Keyring",
	)
	output, err := cmd.Output()
	if err != nil {
		if isUserCancelled(err) {
			return "", ErrUserCancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// promptRofi uses rofi in dmenu mode for password input
func (sm *SessionManager) promptRofi() (string, error) {
	cmd := exec.Command("rofi",
		"-dmenu",
		"-password",
		"-p", "Bitwarden Master Password",
		"-theme-str", "entry { placeholder: \"\"; }",
	)
	output, err := cmd.Output()
	if err != nil {
		if isUserCancelled(err) {
			return "", ErrUserCancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// promptDmenu uses dmenu for password input (no masking, less secure)
func (sm *SessionManager) promptDmenu() (string, error) {
	cmd := exec.Command("dmenu",
		"-p", "Bitwarden Master Password:",
		"-nf", "#000000",
		"-nb", "#000000", // Black on black to "hide" input
	)
	cmd.Stdin = strings.NewReader("") // Empty input
	output, err := cmd.Output()
	if err != nil {
		if isUserCancelled(err) {
			return "", ErrUserCancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// promptSystemd uses systemd-ask-password for password input
func (sm *SessionManager) promptSystemd() (string, error) {
	cmdPath := "systemd-ask-password"
	if sm.systemdAskPasswordPath != "" {
		cmdPath = sm.systemdAskPasswordPath
	}

	cmd := exec.Command(cmdPath,
		"--timeout=120",
		"--icon=dialog-password",
		"Bitwarden Master Password:",
	)
	output, err := cmd.Output()
	if err != nil {
		if isUserCancelled(err) {
			return "", ErrUserCancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
