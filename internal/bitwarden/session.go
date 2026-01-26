package bitwarden

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// SessionManager handles Bitwarden session key management
type SessionManager struct {
	sessionKey string
	mu         sync.RWMutex
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	sm := &SessionManager{}
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
	// Also persist to file
	sm.saveSessionToFile(key)
}

// ClearSession clears the stored session key
func (sm *SessionManager) ClearSession() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessionKey = ""
	sm.deleteSessionFile()
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

	// Try to load from session file
	sessionFile := sm.getSessionFilePath()
	data, err := os.ReadFile(sessionFile)
	if err == nil {
		sm.sessionKey = strings.TrimSpace(string(data))
	}
}

// getSessionFilePath returns the path to the session file
func (sm *SessionManager) getSessionFilePath() string {
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

	// Write session file with restricted permissions
	_ = os.WriteFile(sessionFile, []byte(key), 0600)
}

// deleteSessionFile removes the session file
func (sm *SessionManager) deleteSessionFile() {
	sessionFile := sm.getSessionFilePath()
	_ = os.Remove(sessionFile)
}

// PromptForPassword prompts the user for their master password using a GUI dialog
// It tries various GUI methods, falling back through the chain
func (sm *SessionManager) PromptForPassword() (string, error) {
	// Try zenity (GNOME/GTK)
	if password, err := sm.promptZenity(); err == nil {
		return password, nil
	}

	// Try kdialog (KDE)
	if password, err := sm.promptKDialog(); err == nil {
		return password, nil
	}

	// Try rofi (common on tiling WMs)
	if password, err := sm.promptRofi(); err == nil {
		return password, nil
	}

	// Try dmenu (fallback for tiling WMs)
	if password, err := sm.promptDmenu(); err == nil {
		return password, nil
	}

	// Try systemd-ask-password (works with Plymouth/console)
	if password, err := sm.promptSystemd(); err == nil {
		return password, nil
	}

	return "", fmt.Errorf("no password prompt method available (install zenity, kdialog, or rofi)")
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
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// promptSystemd uses systemd-ask-password for password input
func (sm *SessionManager) promptSystemd() (string, error) {
	cmd := exec.Command("systemd-ask-password",
		"--timeout=120",
		"--icon=dialog-password",
		"Bitwarden Master Password:",
	)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
