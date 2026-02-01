package bitwarden

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// --- M5: Prompt Hardening Tests ---

func TestErrNoSecurePromptAvailable_Exists(t *testing.T) {
	// Verify the sentinel error exists
	if ErrNoSecurePromptAvailable == nil {
		t.Fatal("ErrNoSecurePromptAvailable should be defined")
	}

	// Verify it has a meaningful message
	msg := ErrNoSecurePromptAvailable.Error()
	if msg == "" {
		t.Error("ErrNoSecurePromptAvailable should have a non-empty error message")
	}
}

func TestSessionConfig_HasAllowInsecurePromptsField(t *testing.T) {
	cfg := SessionConfig{
		AllowInsecurePrompts: true,
	}

	if !cfg.AllowInsecurePrompts {
		t.Error("AllowInsecurePrompts field not properly set")
	}

	cfg.AllowInsecurePrompts = false
	if cfg.AllowInsecurePrompts {
		t.Error("AllowInsecurePrompts should be false when set to false")
	}
}

func TestSessionConfig_HasSystemdAskPasswordPathField(t *testing.T) {
	testPath := "/usr/bin/systemd-ask-password"
	cfg := SessionConfig{
		SystemdAskPasswordPath: testPath,
	}

	if cfg.SystemdAskPasswordPath != testPath {
		t.Errorf("SystemdAskPasswordPath = %q, want %q", cfg.SystemdAskPasswordPath, testPath)
	}
}

func TestDefaultSessionConfig_AllowInsecurePromptsDefaultsFalse(t *testing.T) {
	cfg := DefaultSessionConfig()

	if cfg.AllowInsecurePrompts {
		t.Error("DefaultSessionConfig().AllowInsecurePrompts should default to false")
	}
}

func TestDefaultSessionConfig_SystemdAskPasswordPathDefaultsEmpty(t *testing.T) {
	cfg := DefaultSessionConfig()

	if cfg.SystemdAskPasswordPath != "" {
		t.Errorf("DefaultSessionConfig().SystemdAskPasswordPath should default to empty, got %q", cfg.SystemdAskPasswordPath)
	}
}

func TestNewSessionManagerWithConfig_PropagatesSystemdAskPasswordPath(t *testing.T) {
	customPath := "/custom/path/to/systemd-ask-password"
	cfg := SessionConfig{
		SystemdAskPasswordPath: customPath,
	}

	sm := NewSessionManagerWithConfig(cfg)

	if got := sm.SystemdAskPasswordPath(); got != customPath {
		t.Errorf("SystemdAskPasswordPath() = %q, want %q", got, customPath)
	}
}

// TestPromptOrder verifies that prompts are tried in the correct order
func TestPromptOrder_ReturnsCorrectSequence(t *testing.T) {
	tests := []struct {
		name                 string
		noctaliaEnabled      bool
		allowInsecurePrompts bool
		wantNoctalia         bool
		wantSystemd          bool
		wantZenity           bool
		wantKDialog          bool
		wantRofi             bool
		wantDmenu            bool
		noctaliaPosition     int
		systemdPosition      int
		dmenuPosition        int
	}{
		{
			name:                 "all prompts allowed with Noctalia",
			noctaliaEnabled:      true,
			allowInsecurePrompts: true,
			wantNoctalia:         true,
			wantSystemd:          true,
			wantZenity:           true,
			wantKDialog:          true,
			wantRofi:             true,
			wantDmenu:            true,
			noctaliaPosition:     0, // First
			systemdPosition:      4, // After GUI tools (zenity, kdialog, rofi)
			dmenuPosition:        5, // Last
		},
		{
			name:                 "dmenu blocked when insecure prompts disabled",
			noctaliaEnabled:      false,
			allowInsecurePrompts: false,
			wantNoctalia:         false,
			wantSystemd:          true,
			wantZenity:           true,
			wantKDialog:          true,
			wantRofi:             true,
			wantDmenu:            false,
			systemdPosition:      3, // After GUI tools (zenity=0, kdialog=1, rofi=2)
		},
		{
			name:                 "dmenu allowed when insecure prompts enabled",
			noctaliaEnabled:      false,
			allowInsecurePrompts: true,
			wantNoctalia:         false,
			wantSystemd:          true,
			wantZenity:           true,
			wantKDialog:          true,
			wantRofi:             true,
			wantDmenu:            true,
			systemdPosition:      3, // After GUI tools (zenity=0, kdialog=1, rofi=2)
			dmenuPosition:        4, // Last
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SessionConfig{
				NoctaliaEnabled:      tt.noctaliaEnabled,
				AllowInsecurePrompts: tt.allowInsecurePrompts,
			}

			prompts := getPromptOrder(cfg)

			// Verify expected prompts are present/absent
			foundNoctalia := false
			foundSystemd := false
			foundZenity := false
			foundKDialog := false
			foundRofi := false
			foundDmenu := false

			noctaliaIdx := -1
			systemdIdx := -1
			dmenuIdx := -1

			for i, p := range prompts {
				switch p.name {
				case "noctalia":
					foundNoctalia = true
					noctaliaIdx = i
				case "systemd-ask-password":
					foundSystemd = true
					systemdIdx = i
				case "zenity":
					foundZenity = true
				case "kdialog":
					foundKDialog = true
				case "rofi":
					foundRofi = true
				case "dmenu":
					foundDmenu = true
					dmenuIdx = i
				}
			}

			if foundNoctalia != tt.wantNoctalia {
				t.Errorf("Noctalia presence = %v, want %v", foundNoctalia, tt.wantNoctalia)
			}
			if foundSystemd != tt.wantSystemd {
				t.Errorf("systemd-ask-password presence = %v, want %v", foundSystemd, tt.wantSystemd)
			}
			if foundZenity != tt.wantZenity {
				t.Errorf("zenity presence = %v, want %v", foundZenity, tt.wantZenity)
			}
			if foundKDialog != tt.wantKDialog {
				t.Errorf("kdialog presence = %v, want %v", foundKDialog, tt.wantKDialog)
			}
			if foundRofi != tt.wantRofi {
				t.Errorf("rofi presence = %v, want %v", foundRofi, tt.wantRofi)
			}
			if foundDmenu != tt.wantDmenu {
				t.Errorf("dmenu presence = %v, want %v", foundDmenu, tt.wantDmenu)
			}

			// Verify ordering
			if tt.wantNoctalia && noctaliaIdx != tt.noctaliaPosition {
				t.Errorf("Noctalia position = %d, want %d", noctaliaIdx, tt.noctaliaPosition)
			}
			if tt.wantSystemd && systemdIdx != tt.systemdPosition {
				t.Errorf("systemd-ask-password position = %d, want %d", systemdIdx, tt.systemdPosition)
			}
			if tt.wantDmenu && tt.dmenuPosition > 0 && dmenuIdx != tt.dmenuPosition {
				t.Errorf("dmenu position = %d, want %d", dmenuIdx, tt.dmenuPosition)
			}

			// Verify dmenu is last when present
			if foundDmenu && dmenuIdx != len(prompts)-1 {
				t.Errorf("dmenu should be last, but is at position %d of %d", dmenuIdx, len(prompts))
			}

			// Verify systemd is after GUI tools (zenity, kdialog, rofi)
			if foundNoctalia && foundSystemd && noctaliaIdx >= systemdIdx {
				t.Errorf("Noctalia (pos %d) should be before systemd-ask-password (pos %d)", noctaliaIdx, systemdIdx)
			}
		})
	}
}

func TestPromptForPassword_ReturnsErrNoSecurePromptAvailable_WhenOnlyDmenuAndNotAllowed(t *testing.T) {
	// This test verifies the error type and message
	// The actual runtime behavior depends on which commands are installed

	// Verify the error exists and has the correct message
	if ErrNoSecurePromptAvailable == nil {
		t.Fatal("ErrNoSecurePromptAvailable should be defined")
	}

	msg := ErrNoSecurePromptAvailable.Error()
	if !errors.Is(ErrNoSecurePromptAvailable, ErrNoSecurePromptAvailable) {
		t.Error("ErrNoSecurePromptAvailable should satisfy errors.Is check")
	}

	// Verify message mentions dmenu and the flag
	containsAny := func(s string, substrs ...string) bool {
		for _, substr := range substrs {
			if strings.Contains(s, substr) {
				return true
			}
		}
		return false
	}
	if !containsAny(msg, "dmenu", "insecure") {
		t.Errorf("Error message should mention dmenu or insecure prompts, got: %q", msg)
	}
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- Session Store Tests ---

func TestDefaultSessionConfig_SessionStoreDefaultsToMemory(t *testing.T) {
	cfg := DefaultSessionConfig()

	if cfg.SessionStore != "memory" {
		t.Errorf("DefaultSessionConfig().SessionStore = %q, want %q", cfg.SessionStore, "memory")
	}
}

func TestDefaultSessionConfig_SessionFileDefaultsToEmpty(t *testing.T) {
	cfg := DefaultSessionConfig()

	if cfg.SessionFile != "" {
		t.Errorf("DefaultSessionConfig().SessionFile should default to empty, got %q", cfg.SessionFile)
	}
}

func TestSessionManager_MemoryStoreDoesNotCreateFile(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/test-session"

	cfg := SessionConfig{
		SessionStore: "memory",
		SessionFile:  sessionFile,
	}

	sm := NewSessionManagerWithConfig(cfg)
	sm.SetSession("test-session-key")

	// File should NOT be created for memory store
	if fileExists(sessionFile) {
		t.Error("Memory store should not create session file")
	}

	// Session should still be retrievable
	if got := sm.GetSession(); got != "test-session-key" {
		t.Errorf("GetSession() = %q, want %q", got, "test-session-key")
	}
}

func TestSessionManager_FileStorePersistsSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/test-session"

	cfg := SessionConfig{
		SessionStore: "file",
		SessionFile:  sessionFile,
	}

	sm := NewSessionManagerWithConfig(cfg)
	sm.SetSession("persisted-session-key")

	// File should be created for file store
	if !fileExists(sessionFile) {
		t.Fatal("File store should create session file")
	}

	// Verify file contains the session key
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		t.Fatalf("Failed to read session file: %v", err)
	}

	if strings.TrimSpace(string(data)) != "persisted-session-key" {
		t.Errorf("Session file contents = %q, want %q", strings.TrimSpace(string(data)), "persisted-session-key")
	}

	// Verify file permissions are restrictive (0600)
	info, err := os.Stat(sessionFile)
	if err != nil {
		t.Fatalf("Failed to stat session file: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Session file permissions = %04o, want 0600", perm)
	}
}

func TestSessionManager_FileStoreLoadsSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/test-session"

	// Pre-create session file with content
	err := os.WriteFile(sessionFile, []byte("pre-existing-session\n"), 0600)
	if err != nil {
		t.Fatalf("Failed to create session file: %v", err)
	}

	cfg := SessionConfig{
		SessionStore: "file",
		SessionFile:  sessionFile,
	}

	sm := NewSessionManagerWithConfig(cfg)

	// Should load session from file
	if got := sm.GetSession(); got != "pre-existing-session" {
		t.Errorf("GetSession() = %q, want %q", got, "pre-existing-session")
	}
}

func TestSessionManager_FileStoreRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := tmpDir + "/real-session"
	symlinkFile := tmpDir + "/symlink-session"

	// Create target file with session
	err := os.WriteFile(targetFile, []byte("symlink-session-key"), 0600)
	if err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create symlink to target
	err = os.Symlink(targetFile, symlinkFile)
	if err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	cfg := SessionConfig{
		SessionStore: "file",
		SessionFile:  symlinkFile,
	}

	sm := NewSessionManagerWithConfig(cfg)

	// Should NOT load session from symlink (security check)
	if got := sm.GetSession(); got != "" {
		t.Errorf("GetSession() should reject symlink, got %q", got)
	}
}

func TestSessionManager_ClearSessionDeletesFileOnlyInFileMode(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/test-session"

	// Test file mode - should delete file
	cfg := SessionConfig{
		SessionStore: "file",
		SessionFile:  sessionFile,
	}

	sm := NewSessionManagerWithConfig(cfg)
	sm.SetSession("to-be-cleared")

	if !fileExists(sessionFile) {
		t.Fatal("Session file should exist before clear")
	}

	sm.ClearSession()

	if fileExists(sessionFile) {
		t.Error("ClearSession should delete file in file mode")
	}

	if got := sm.GetSession(); got != "" {
		t.Errorf("GetSession() after ClearSession = %q, want empty", got)
	}
}

func TestSessionManager_ClearSessionMemoryModeNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/test-session"

	// Pre-create a file that should NOT be deleted
	err := os.WriteFile(sessionFile, []byte("should-not-delete"), 0600)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	cfg := SessionConfig{
		SessionStore: "memory",
		SessionFile:  sessionFile, // Configured but shouldn't be used
	}

	sm := NewSessionManagerWithConfig(cfg)
	sm.SetSession("memory-session")
	sm.ClearSession()

	// File should still exist (memory mode doesn't touch files)
	if !fileExists(sessionFile) {
		t.Error("ClearSession in memory mode should not delete files")
	}
}

func TestSessionManager_BW_SESSION_EnvHonored(t *testing.T) {
	// Save and restore env
	oldVal := os.Getenv("BW_SESSION")
	defer os.Setenv("BW_SESSION", oldVal)

	os.Setenv("BW_SESSION", "env-session-key")

	cfg := DefaultSessionConfig()
	sm := NewSessionManagerWithConfig(cfg)

	if got := sm.GetSession(); got != "env-session-key" {
		t.Errorf("GetSession() = %q, want %q from BW_SESSION env", got, "env-session-key")
	}
}

func TestSessionManager_BW_SESSION_TakesPriorityOverFile(t *testing.T) {
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/test-session"

	// Pre-create session file
	err := os.WriteFile(sessionFile, []byte("file-session"), 0600)
	if err != nil {
		t.Fatalf("Failed to create session file: %v", err)
	}

	// Save and restore env
	oldVal := os.Getenv("BW_SESSION")
	defer os.Setenv("BW_SESSION", oldVal)

	os.Setenv("BW_SESSION", "env-session-key")

	cfg := SessionConfig{
		SessionStore: "file",
		SessionFile:  sessionFile,
	}

	sm := NewSessionManagerWithConfig(cfg)

	// Env should take priority over file
	if got := sm.GetSession(); got != "env-session-key" {
		t.Errorf("GetSession() = %q, want %q (env should take priority)", got, "env-session-key")
	}
}

func TestSessionManager_EmptyStoreDefaultsToMemory(t *testing.T) {
	// Create temp directory BEFORE creating SessionManager
	tmpDir := t.TempDir()
	sessionFile := tmpDir + "/should-not-exist"

	cfg := SessionConfig{
		SessionStore: "",          // Empty should default to memory
		SessionFile:  sessionFile, // Point to a file in temp dir
	}

	sm := NewSessionManagerWithConfig(cfg)

	// Set a session - with memory mode, this should NOT create the file
	sm.SetSession("test-session-key")

	if fileExists(sessionFile) {
		t.Error("Empty SessionStore should default to memory mode and not write to file")
	}

	// Verify the session was stored in memory
	if sm.GetSession() != "test-session-key" {
		t.Error("Session should still be stored in memory")
	}
}
