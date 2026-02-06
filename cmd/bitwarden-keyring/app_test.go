package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// setupSystemdSocket creates a fake XDG_RUNTIME_DIR with systemd/private
// so isSystemdUserRunning() returns true.
func setupSystemdSocket(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", tmpDir)
	systemdDir := filepath.Join(tmpDir, "systemd")
	if err := os.MkdirAll(systemdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(systemdDir, "private"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	return tmpDir
}

// installFakeCommand creates a fake executable shell script in a temp dir
// and prepends it to PATH. The script writes its arguments to a marker file
// so the test can verify what was invoked.
func installFakeCommand(t *testing.T, name string, exitCode int) string {
	t.Helper()
	binDir := t.TempDir()
	markerFile := filepath.Join(binDir, name+".args")

	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\nexit %d\n", markerFile, exitCode)

	scriptPath := filepath.Join(binDir, name)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	return markerFile
}

func TestExportSSHAuthSock(t *testing.T) {
	tests := []struct {
		name           string
		socketPath     string
		setupSystemd   bool
		installCmd     bool
		cmdExitCode    int
		wantErr        bool
		wantCmdInvoked bool
		wantArgs       string
	}{
		{
			name:           "exports via dbus-update-activation-environment when systemd running",
			socketPath:     "/tmp/test-ssh.sock",
			setupSystemd:   true,
			installCmd:     true,
			cmdExitCode:    0,
			wantErr:        false,
			wantCmdInvoked: true,
			wantArgs:       "SSH_AUTH_SOCK=/tmp/test-ssh.sock",
		},
		{
			name:           "skips when systemd not running",
			socketPath:     "/tmp/test-ssh.sock",
			setupSystemd:   false,
			installCmd:     true,
			cmdExitCode:    0,
			wantErr:        false,
			wantCmdInvoked: false,
		},
		{
			name:           "skips gracefully when command not found",
			socketPath:     "/tmp/test-ssh.sock",
			setupSystemd:   true,
			installCmd:     false,
			wantErr:        false,
			wantCmdInvoked: false,
		},
		{
			name:           "returns error when command fails",
			socketPath:     "/tmp/test-ssh.sock",
			setupSystemd:   true,
			installCmd:     true,
			cmdExitCode:    1,
			wantErr:        true,
			wantCmdInvoked: true,
			wantArgs:       "SSH_AUTH_SOCK=/tmp/test-ssh.sock",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure no systemd socket by default
			t.Setenv("XDG_RUNTIME_DIR", "")

			var markerFile string
			if tt.setupSystemd {
				setupSystemdSocket(t)
			}
			if tt.installCmd {
				markerFile = installFakeCommand(t, "dbus-update-activation-environment", tt.cmdExitCode)
			}

			err := exportSSHAuthSock(tt.socketPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("exportSSHAuthSock() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantCmdInvoked {
				args, readErr := os.ReadFile(markerFile)
				if readErr != nil {
					t.Fatalf("expected command to be invoked, but marker file not found: %v", readErr)
				}
				got := string(args)
				// Trim trailing newline from shell echo
				got = got[:len(got)-1]
				if got != tt.wantArgs {
					t.Errorf("command args = %q, want %q", got, tt.wantArgs)
				}
			} else if markerFile != "" {
				if _, statErr := os.Stat(markerFile); statErr == nil {
					t.Error("expected command NOT to be invoked, but marker file exists")
				}
			}
		})
	}
}

func TestIsSystemdUserRunning(t *testing.T) {
	tests := []struct {
		name           string
		setupRuntime   bool
		createSockFile bool
		want           bool
	}{
		{
			name:           "returns true when systemd private socket exists",
			setupRuntime:   true,
			createSockFile: true,
			want:           true,
		},
		{
			name:           "returns false when systemd dir missing",
			setupRuntime:   true,
			createSockFile: false,
			want:           false,
		},
		{
			name:           "returns false when XDG_RUNTIME_DIR unset",
			setupRuntime:   false,
			createSockFile: false,
			want:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupRuntime {
				tmpDir := t.TempDir()
				t.Setenv("XDG_RUNTIME_DIR", tmpDir)
				if tt.createSockFile {
					systemdDir := filepath.Join(tmpDir, "systemd")
					if err := os.MkdirAll(systemdDir, 0o700); err != nil {
						t.Fatal(err)
					}
					// Create a fake private socket file
					f, err := os.Create(filepath.Join(systemdDir, "private"))
					if err != nil {
						t.Fatal(err)
					}
					f.Close()
				}
			} else {
				t.Setenv("XDG_RUNTIME_DIR", "")
			}

			got := isSystemdUserRunning()
			if got != tt.want {
				t.Errorf("isSystemdUserRunning() = %v, want %v", got, tt.want)
			}
		})
	}
}
