package bitwarden

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/joe/bitwarden-keyring/internal/logging"
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

// runPromptCommand executes a GUI prompt command and returns the trimmed output.
// If the command fails with a user cancellation (exit code 1 or 5), it returns ErrUserCancelled.
func runPromptCommand(cmd *exec.Cmd) (string, error) {
	output, err := cmd.Output()
	if err != nil {
		if isUserCancelled(err) {
			return "", ErrUserCancelled
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
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
	// MaxPasswordRetries is the maximum number of password attempts before giving up (default: 3)
	MaxPasswordRetries int
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
		MaxPasswordRetries:     3,
	}
}

// SessionManager handles Bitwarden session key management
type SessionManager struct {
	sessionKey             string
	mu                     sync.RWMutex
	noctaliaClient         *noctalia.Client
	noctaliaEnabled        bool
	noctaliaSession        *noctalia.PasswordSession // Active Noctalia session for retry support
	allowInsecurePrompts   bool
	systemdAskPasswordPath string
	pathDiscoveryWarned    bool
	sessionStore           string
	sessionFile            string
	maxPasswordRetries     int
}

// NewSessionManager creates a new session manager with default config
func NewSessionManager() *SessionManager {
	return NewSessionManagerWithConfig(DefaultSessionConfig())
}

// NewSessionManagerWithConfig creates a new session manager with the given config
func NewSessionManagerWithConfig(cfg SessionConfig) *SessionManager {
	maxRetries := cfg.MaxPasswordRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	sm := &SessionManager{
		noctaliaEnabled:        cfg.NoctaliaEnabled,
		allowInsecurePrompts:   cfg.AllowInsecurePrompts,
		systemdAskPasswordPath: cfg.SystemdAskPasswordPath,
		sessionStore:           cfg.SessionStore,
		sessionFile:            cfg.SessionFile,
		maxPasswordRetries:     maxRetries,
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

// SystemdAskPasswordPath returns the configured path for systemd-ask-password.
func (sm *SessionManager) SystemdAskPasswordPath() string {
	return sm.systemdAskPasswordPath
}

// MaxPasswordRetries returns the maximum number of password retry attempts.
func (sm *SessionManager) MaxPasswordRetries() int {
	return sm.maxPasswordRetries
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
		logging.L.Warn("session file is a symlink, rejecting", "path", sessionFile)
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

	// Check if the parent directory is a symlink (security check)
	if dirInfo, err := os.Lstat(dir); err == nil {
		if dirInfo.Mode()&os.ModeSymlink != 0 {
			logging.L.Warn("session directory is a symlink, refusing to save", "path", dir)
			return
		}
	}

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
			logging.L.Warn("session directory has insecure permissions (group/world-writable)", "path", dir, "mode", fmt.Sprintf("%04o", mode))
		}
	}

	// Check if session file is already a symlink (best-effort pre-check)
	if fileInfo, err := os.Lstat(sessionFile); err == nil {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			logging.L.Warn("session file is a symlink, refusing to save", "path", sessionFile)
			return
		}
	}

	// Open file with O_NOFOLLOW to prevent following symlinks (TOCTOU protection)
	// This will fail with ELOOP if the file is a symlink
	fd, err := os.OpenFile(sessionFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			logging.L.Warn("session file is a symlink, refusing to save", "path", sessionFile)
		} else {
			logging.L.Warn("failed to open session file for writing", "error", err)
		}
		return
	}
	defer func() {
		if err := fd.Close(); err != nil {
			logging.L.Warn("failed to close session file", "error", err)
		}
	}()

	// Verify the opened file is a regular file (not FIFO, device, directory)
	fi, err := fd.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		logging.L.Warn("session file is not a regular file, refusing to write")
		return
	}

	// Ensure permissions are 0600 (in case file already existed with different perms)
	if err := fd.Chmod(0600); err != nil {
		logging.L.Warn("failed to set session file permissions", "error", err)
	}

	// Write session key
	if _, err := fd.WriteString(key); err != nil {
		logging.L.Warn("failed to write session file", "error", err)
		return
	}
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

	// 2. zenity (GNOME/GTK GUI)
	prompts = append(prompts, promptMethod{name: "zenity"})

	// 3. kdialog (KDE GUI)
	prompts = append(prompts, promptMethod{name: "kdialog"})

	// 4. rofi (tiling WM GUI)
	prompts = append(prompts, promptMethod{name: "rofi"})

	// 5. systemd-ask-password (TTY/console fallback)
	prompts = append(prompts, promptMethod{name: "systemd-ask-password"})

	// 6. dmenu (only if AllowInsecurePrompts)
	if cfg.AllowInsecurePrompts {
		prompts = append(prompts, promptMethod{name: "dmenu"})
	}

	return prompts
}

// PromptForPassword prompts the user for their master password using a GUI dialog.
// If errMsg is non-empty, it's displayed as part of the prompt (for retry feedback).
// It tries various GUI methods, falling back through the chain in order of security.
// Returns the password, an optional ResultNotifier for two-phase communication, and an error.
func (sm *SessionManager) PromptForPassword(errMsg string) (string, ResultNotifier, error) {
	// Build minimal config from session manager fields
	cfg := SessionConfig{
		NoctaliaEnabled:      sm.noctaliaEnabled,
		AllowInsecurePrompts: sm.allowInsecurePrompts,
	}

	// Get the ordered list of prompts to try
	prompts := getPromptOrder(cfg)

	// Log one-time warning about PATH discovery (before trying any prompt)
	if !sm.pathDiscoveryWarned {
		logging.L.Debug("using PATH discovery for prompt tools - consider specifying absolute paths")
		sm.pathDiscoveryWarned = true
	}

	// Try each prompt method in order
	for _, method := range prompts {
		switch method.name {
		case "noctalia":
			if sm.noctaliaClient == nil {
				continue
			}
			password, notifier, err := sm.promptNoctalia(errMsg)
			if err == nil {
				return password, notifier, nil
			}
			if errors.Is(err, noctalia.ErrCancelled) {
				// User explicitly cancelled - don't try fallback methods
				return "", nil, ErrUserCancelled
			}
			if !errors.Is(err, noctalia.ErrSocketNotFound) && !errors.Is(err, noctalia.ErrConnectionFailed) {
				// Only log non-connection errors (connection errors just mean agent isn't running)
				logging.L.Info("noctalia prompt failed, trying fallback methods", "error", err)
			}

		case "zenity":
			if !commandExists("zenity") {
				continue
			}
			password, err := sm.promptZenity(errMsg)
			if err == nil {
				return password, nil, nil
			}
			if errors.Is(err, ErrUserCancelled) {
				return "", nil, err
			}

		case "kdialog":
			if !commandExists("kdialog") {
				continue
			}
			password, err := sm.promptKDialog(errMsg)
			if err == nil {
				return password, nil, nil
			}
			if errors.Is(err, ErrUserCancelled) {
				return "", nil, err
			}

		case "rofi":
			if !commandExists("rofi") {
				continue
			}
			password, err := sm.promptRofi(errMsg)
			if err == nil {
				return password, nil, nil
			}
			if errors.Is(err, ErrUserCancelled) {
				return "", nil, err
			}

		case "systemd-ask-password":
			if !commandExists("systemd-ask-password") {
				continue
			}
			password, err := sm.promptSystemd(errMsg)
			if err == nil {
				return password, nil, nil
			}
			if errors.Is(err, ErrUserCancelled) {
				return "", nil, err
			}

		case "dmenu":
			if !commandExists("dmenu") {
				continue
			}
			password, err := sm.promptDmenu(errMsg)
			if err == nil {
				return password, nil, nil
			}
			if errors.Is(err, ErrUserCancelled) {
				return "", nil, err
			}

		default:
			logging.L.Debug("unknown prompt method, skipping", "method", method.name)
		}
	}

	// Check if only dmenu is available but not allowed (special error case)
	if !cfg.AllowInsecurePrompts && commandExists("dmenu") {
		return "", nil, ErrNoSecurePromptAvailable
	}

	return "", nil, fmt.Errorf("no password prompt method available (install zenity, kdialog, rofi, or systemd-ask-password)")
}

// promptNoctalia uses the Noctalia agent for a password dialog with two-phase retry support.
// Returns the password, a notifier function for sending results, and an error.
func (sm *SessionManager) promptNoctalia(errMsg string) (string, ResultNotifier, error) {
	if sm.noctaliaClient == nil {
		return "", nil, noctalia.ErrSocketNotFound
	}

	if !sm.noctaliaClient.IsAvailable() {
		return "", nil, noctalia.ErrSocketNotFound
	}

	// Check if we have an existing session waiting for retry
	if sm.noctaliaSession != nil && errMsg != "" {
		// Wait for the user to enter a new password on the existing session
		password, err := sm.noctaliaSession.WaitForRetry(context.Background(), noctalia.DefaultTimeout)
		if err != nil {
			sm.noctaliaSession = nil
			if errors.Is(err, noctalia.ErrCancelled) {
				return "", nil, err
			}
			// Session failed, will need to create a new one on next attempt
			return "", nil, err
		}

		// Return notifier that uses the existing session
		notifier := func(success bool, errMsg string, allowRetry bool) {
			if sm.noctaliaSession != nil {
				_ = sm.noctaliaSession.SendResult(success, errMsg, allowRetry)
				if success || !allowRetry {
					sm.noctaliaSession = nil
				}
			}
		}
		return password, notifier, nil
	}

	// Create a new session
	ctx, cancel := context.WithTimeout(context.Background(), noctalia.DefaultTimeout)
	defer cancel()

	message := "Enter your Bitwarden Master Password:"
	if errMsg != "" {
		message = errMsg + "\n" + message
	}

	password, session, err := sm.noctaliaClient.RequestPasswordWithSession(ctx, "Bitwarden Keyring", message)
	if err != nil {
		return "", nil, err
	}

	// Store the session for potential retry
	sm.noctaliaSession = session

	// Create notifier that uses the session
	notifier := func(success bool, errMsg string, allowRetry bool) {
		if sm.noctaliaSession != nil {
			_ = sm.noctaliaSession.SendResult(success, errMsg, allowRetry)
			if success || !allowRetry {
				sm.noctaliaSession = nil
			}
		}
	}

	return password, notifier, nil
}

// promptZenity uses zenity for a GTK password dialog
func (sm *SessionManager) promptZenity(errMsg string) (string, error) {
	text := "Enter your Bitwarden Master Password:"
	if errMsg != "" {
		text = errMsg + "\n" + text
	}
	return runPromptCommand(exec.Command("zenity",
		"--password",
		"--title=Bitwarden Keyring",
		"--text="+text,
		"--timeout=120",
	))
}

// promptKDialog uses kdialog for a KDE password dialog
func (sm *SessionManager) promptKDialog(errMsg string) (string, error) {
	message := "Enter your Bitwarden Master Password:"
	if errMsg != "" {
		message = errMsg + "\n" + message
	}
	return runPromptCommand(exec.Command("kdialog",
		"--password",
		message,
		"--title", "Bitwarden Keyring",
	))
}

// promptRofi uses rofi in dmenu mode for password input
func (sm *SessionManager) promptRofi(errMsg string) (string, error) {
	args := []string{
		"-dmenu",
		"-password",
		"-p", "Bitwarden Master Password",
		"-theme-str", "entry { placeholder: \"\"; }",
	}
	if errMsg != "" {
		args = append(args, "-mesg", errMsg)
	}
	return runPromptCommand(exec.Command("rofi", args...))
}

// promptDmenu uses dmenu for password input (no masking, less secure)
func (sm *SessionManager) promptDmenu(errMsg string) (string, error) {
	prompt := "Bitwarden Master Password:"
	if errMsg != "" {
		prompt = errMsg + " - " + prompt
	}
	cmd := exec.Command("dmenu",
		"-p", prompt,
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
func (sm *SessionManager) promptSystemd(errMsg string) (string, error) {
	cmdPath := "systemd-ask-password"
	if sm.systemdAskPasswordPath != "" {
		cmdPath = sm.systemdAskPasswordPath
	}
	prompt := "Bitwarden Master Password:"
	if errMsg != "" {
		prompt = errMsg + " - " + prompt
	}
	return runPromptCommand(exec.Command(cmdPath,
		"--timeout=120",
		"--icon=dialog-password",
		prompt,
	))
}
