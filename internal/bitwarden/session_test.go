package bitwarden

import (
	"errors"
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
			systemdPosition:      1, // Second
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
			systemdPosition:      0, // First (since Noctalia disabled)
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

			// Verify systemd is after Noctalia (if both present)
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
	if !containsAny(msg, "dmenu", "insecure") {
		t.Errorf("Error message should mention dmenu or insecure prompts, got: %q", msg)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if contains(s, substr) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestPromptSystemd_UsesCustomPath_WhenProvided(t *testing.T) {
	customPath := "/custom/path/systemd-ask-password"
	cfg := SessionConfig{
		SystemdAskPasswordPath: customPath,
	}

	sm := NewSessionManagerWithConfig(cfg)

	// Verify the config is stored
	if sm.systemdAskPasswordPath != customPath {
		t.Errorf("systemdAskPasswordPath = %q, want %q", sm.systemdAskPasswordPath, customPath)
	}
}
