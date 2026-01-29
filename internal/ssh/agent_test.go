package ssh

import (
	"context"
	"errors"
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
