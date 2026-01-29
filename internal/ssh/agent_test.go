package ssh

import (
	"context"
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

	// Create a stale socket file
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("Failed to create stale socket: %v", err)
	}
	f.Close()

	client := bitwarden.NewClient(8087)
	server := NewServer(socketPath, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should succeed by removing stale socket
	if err := server.Start(ctx); err != nil {
		t.Fatalf("Start() should remove stale socket, error = %v", err)
	}

	server.Stop()
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
	originalXDG := os.Getenv("XDG_RUNTIME_DIR")
	defer os.Setenv("XDG_RUNTIME_DIR", originalXDG)

	os.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	path := DefaultSocketPath()
	expected := "/run/user/1000/bitwarden-keyring/ssh.sock"
	if path != expected {
		t.Errorf("DefaultSocketPath() with XDG_RUNTIME_DIR = %v, want %v", path, expected)
	}

	// Test without XDG_RUNTIME_DIR
	os.Unsetenv("XDG_RUNTIME_DIR")
	path = DefaultSocketPath()
	expected = "/tmp/bitwarden-keyring-ssh.sock"
	if path != expected {
		t.Errorf("DefaultSocketPath() without XDG_RUNTIME_DIR = %v, want %v", path, expected)
	}
}
