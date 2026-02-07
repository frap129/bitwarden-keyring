package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

func TestServer_SocketPath(t *testing.T) {
	socketPath := "/tmp/test-ssh-agent.sock"
	server := NewServer(socketPath, nil)

	if server.SocketPath() != socketPath {
		t.Errorf("SocketPath() = %v, want %v", server.SocketPath(), socketPath)
	}
}

func TestServer_StartStop(t *testing.T) {
	// Use a temporary directory for the socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ssh.sock")

	// Create a mock client - we won't actually use it for this test
	client := bitwarden.NewClient(8087)

	server := NewServer(socketPath, client)
	server.SetDebug(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the server
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Verify socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("Socket file should exist after Start()")
	}

	// Verify we can connect
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Errorf("Failed to connect to socket: %v", err)
	} else {
		conn.Close()
	}

	// Stop the server
	if err := server.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Give it a moment to clean up
	time.Sleep(100 * time.Millisecond)

	// Verify socket is removed
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("Socket file should be removed after Stop()")
	}
}

func TestServer_StaleSocketRemoval(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ssh.sock")

	// Create a server, start it, then stop it without removing the socket manually
	// This simulates a stale socket from a previous run
	client := bitwarden.NewClient(8087)
	server1 := NewServer(socketPath, client)

	ctx, cancel := context.WithCancel(context.Background())

	if err := server1.Start(ctx); err != nil {
		t.Fatalf("First Start() error = %v", err)
	}

	// Stop the server (which removes the socket)
	cancel()
	server1.Stop()

	// Manually recreate a stale socket by creating a new listener and immediately closing it
	// But leave the file behind by using the lower-level syscall
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create socket: %v", err)
	}

	// Get the socket file to verify it exists before closing
	_, err = os.Stat(socketPath)
	if err != nil {
		listener.Close()
		t.Fatalf("Socket should exist while listener is open: %v", err)
	}

	// Close the listener - on some systems this removes the socket file
	listener.Close()

	// If the socket file was removed, skip this test
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Skip("Socket file was removed when listener closed - cannot test stale socket removal")
	}

	// Now try to start a new server - it should remove the stale socket
	server2 := NewServer(socketPath, client)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	if err := server2.Start(ctx2); err != nil {
		t.Fatalf("Start() should remove stale socket, error = %v", err)
	}

	server2.Stop()
}

func TestServer_NotSocketError(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ssh.sock")

	// Create a regular file (not a socket)
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	f.Close()

	client := bitwarden.NewClient(8087)
	server := NewServer(socketPath, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should fail with ErrNotSocket
	err = server.Start(ctx)
	if err == nil {
		server.Stop()
		t.Fatal("Start() should fail when path is a regular file, not a socket")
	}

	// Verify it's the correct error
	if !errors.Is(err, ErrNotSocket) {
		t.Errorf("Expected ErrNotSocket, got: %v", err)
	}
}

func TestServer_SocketInUse(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "ssh.sock")

	client := bitwarden.NewClient(8087)

	// Start first server
	server1 := NewServer(socketPath, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server1.Start(ctx); err != nil {
		t.Fatalf("First Start() error = %v", err)
	}
	defer server1.Stop()

	// Try to start second server on same socket
	server2 := NewServer(socketPath, client)
	err := server2.Start(ctx)
	if err == nil {
		server2.Stop()
		t.Error("Second Start() should fail when socket is in use")
	}
}

func TestDefaultSocketPath(t *testing.T) {
	// Test with XDG_RUNTIME_DIR set
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	path := DefaultSocketPath()
	expected := "/run/user/1000/bitwarden-keyring/ssh.sock"
	if path != expected {
		t.Errorf("DefaultSocketPath() with XDG_RUNTIME_DIR = %v, want %v", path, expected)
	}

	// Test without XDG_RUNTIME_DIR
	t.Setenv("XDG_RUNTIME_DIR", "")
	path = DefaultSocketPath()
	uid := os.Geteuid()
	expected = filepath.Join(os.TempDir(), fmt.Sprintf("bitwarden-keyring-%d", uid), "ssh.sock")
	if path != expected {
		t.Errorf("DefaultSocketPath() without XDG_RUNTIME_DIR = %v, want %v", path, expected)
	}
}

func TestDefaultSocketPath_TmpFallback_UsesSubdirectory(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	path := DefaultSocketPath()
	// Should be like /tmp/bitwarden-keyring-<uid>/ssh.sock
	uid := os.Geteuid()
	expected := filepath.Join(os.TempDir(), fmt.Sprintf("bitwarden-keyring-%d", uid), "ssh.sock")
	if path != expected {
		t.Errorf("got %q, want %q", path, expected)
	}
}

func TestServer_Start_RejectsSymlinkedSocketDir(t *testing.T) {
	// Create a temp directory for our test
	tmpDir := t.TempDir()

	// Create a "real" directory
	realDir := filepath.Join(tmpDir, "real")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatalf("Failed to create real directory: %v", err)
	}

	// Create a symlink pointing to the real directory
	symlinkDir := filepath.Join(tmpDir, "symlink")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	socketPath := filepath.Join(symlinkDir, "ssh.sock")
	client := bitwarden.NewClient(8087)
	server := NewServer(socketPath, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := server.Start(ctx)
	if err == nil {
		server.Stop()
		t.Fatal("Start() should reject symlinked socket directory")
	}

	if !errors.Is(err, ErrInsecureSocketDir) {
		t.Errorf("Expected ErrInsecureSocketDir, got: %v", err)
	}
}

func TestServer_Start_RejectsWrongOwnerSocketDir(t *testing.T) {
	// This test requires creating a directory owned by a different user.
	// In most test environments, this is not possible without root privileges.
	// We skip this test since we cannot reliably create a directory with
	// a different owner in a standard unit test environment.
	t.Skip("Skipping test - cannot reliably create directory with different owner in unit test")
}

func TestServer_Start_FixesWorldWritableSocketDir(t *testing.T) {
	tmpDir := t.TempDir()
	socketDir := filepath.Join(tmpDir, "world-writable")
	// Create directory with world-writable permissions
	if err := os.MkdirAll(socketDir, 0777); err != nil {
		t.Fatalf("Failed to create socket directory: %v", err)
	}

	// Verify it was created with world-writable permissions
	fi, err := os.Stat(socketDir)
	if err != nil {
		t.Fatalf("Failed to stat socket directory: %v", err)
	}
	if fi.Mode().Perm()&0077 == 0 {
		t.Skip("Directory permissions were already restricted by umask")
	}

	socketPath := filepath.Join(socketDir, "ssh.sock")
	client := bitwarden.NewClient(8087)
	server := NewServer(socketPath, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Server should start successfully by fixing permissions
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start() should fix world-writable permissions and succeed: %v", err)
	}
	server.Stop()

	// Verify permissions were fixed
	fi, err = os.Stat(socketDir)
	if err != nil {
		t.Fatalf("Failed to stat socket directory after Start: %v", err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		t.Errorf("Directory permissions should be restricted to 0700, got: %04o", fi.Mode().Perm())
	}
}
