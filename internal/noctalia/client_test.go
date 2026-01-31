package noctalia

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// MockServer simulates the noctalia-polkit-agent for testing
type MockServer struct {
	listener     net.Listener
	socketPath   string
	responseChan chan KeyringResponse
	requestChan  chan KeyringRequest
}

// NewMockServer creates a new mock server at the given socket path
func NewMockServer(t *testing.T, socketPath string) *MockServer {
	t.Helper()

	// Remove any existing socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}

	m := &MockServer{
		listener:     listener,
		socketPath:   socketPath,
		responseChan: make(chan KeyringResponse, 1),
		requestChan:  make(chan KeyringRequest, 1),
	}

	// Start accepting connections
	go m.acceptLoop(t)

	return m
}

func (m *MockServer) acceptLoop(t *testing.T) {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			// Listener closed
			return
		}
		go m.handleConnection(t, conn)
	}
}

func (m *MockServer) handleConnection(t *testing.T, conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Logf("Mock server: failed to read request: %v", err)
		return
	}

	var req KeyringRequest
	if err := json.Unmarshal(line, &req); err != nil {
		t.Logf("Mock server: failed to parse request: %v", err)
		return
	}

	// Send request to channel for test inspection
	select {
	case m.requestChan <- req:
	default:
	}

	// Wait for response to send
	resp := <-m.responseChan

	// Ensure the ID matches the request cookie
	if resp.ID == "" {
		resp.ID = req.Cookie
	}

	respBytes, _ := json.Marshal(resp)
	respBytes = append(respBytes, '\n')
	conn.Write(respBytes)
}

// RespondWith queues a response to be sent for the next request
func (m *MockServer) RespondWith(resp KeyringResponse) {
	m.responseChan <- resp
}

// GetRequest returns the last received request (blocks until one is received)
func (m *MockServer) GetRequest(t *testing.T, timeout time.Duration) KeyringRequest {
	t.Helper()
	select {
	case req := <-m.requestChan:
		return req
	case <-time.After(timeout):
		t.Fatal("Timeout waiting for request")
		return KeyringRequest{}
	}
}

// Close shuts down the mock server
func (m *MockServer) Close() {
	m.listener.Close()
	os.Remove(m.socketPath)
}

func TestClient_IsAvailable_SocketExists(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create mock server (creates socket)
	server := NewMockServer(t, socketPath)
	defer server.Close()

	client := NewClient(WithSocketPath(socketPath))

	if !client.IsAvailable() {
		t.Error("IsAvailable() = false, want true when socket exists")
	}
}

func TestClient_IsAvailable_SocketMissing(t *testing.T) {
	client := NewClient(WithSocketPath("/nonexistent/path/test.sock"))

	if client.IsAvailable() {
		t.Error("IsAvailable() = true, want false when socket doesn't exist")
	}
}

func TestClient_RequestPassword_Success(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMockServer(t, socketPath)
	defer server.Close()

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	// Queue response
	go func() {
		req := server.GetRequest(t, 2*time.Second)
		if req.Type != "keyring_request" {
			t.Errorf("Expected type keyring_request, got %s", req.Type)
		}
		if req.Title != "Test Title" {
			t.Errorf("Expected title 'Test Title', got %s", req.Title)
		}
		server.RespondWith(KeyringResponse{
			Type:     "keyring_response",
			ID:       req.Cookie,
			Result:   ResultOK,
			Password: "secret123",
		})
	}()

	ctx := context.Background()
	password, err := client.RequestPassword(ctx, "Test Title", "Enter password")

	if err != nil {
		t.Fatalf("RequestPassword() error = %v", err)
	}
	if password != "secret123" {
		t.Errorf("RequestPassword() = %q, want %q", password, "secret123")
	}
}

func TestClient_RequestPassword_Cancelled(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMockServer(t, socketPath)
	defer server.Close()

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	// Queue cancellation response
	go func() {
		req := server.GetRequest(t, 2*time.Second)
		server.RespondWith(KeyringResponse{
			Type:   "keyring_response",
			ID:     req.Cookie,
			Result: ResultCancelled,
		})
	}()

	ctx := context.Background()
	_, err := client.RequestPassword(ctx, "Test", "Enter password")

	if err != ErrCancelled {
		t.Errorf("RequestPassword() error = %v, want ErrCancelled", err)
	}
}

func TestClient_RequestPassword_Timeout(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMockServer(t, socketPath)
	defer server.Close()

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(100*time.Millisecond),
	)

	// Don't respond - let it timeout
	ctx := context.Background()
	_, err := client.RequestPassword(ctx, "Test", "Enter password")

	if err != ErrTimeout {
		t.Errorf("RequestPassword() error = %v, want ErrTimeout", err)
	}
}

func TestClient_RequestPassword_SocketNotFound(t *testing.T) {
	client := NewClient(WithSocketPath("/nonexistent/path/test.sock"))

	ctx := context.Background()
	_, err := client.RequestPassword(ctx, "Test", "Enter password")

	if err != ErrSocketNotFound {
		t.Errorf("RequestPassword() error = %v, want ErrSocketNotFound", err)
	}
}

func TestClient_RequestPassword_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a simple listener that sends invalid JSON
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		defer conn.Close()
		// Read request
		reader := bufio.NewReader(conn)
		reader.ReadBytes('\n')
		// Send invalid JSON
		conn.Write([]byte("not valid json\n"))
	}()

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	ctx := context.Background()
	_, err = client.RequestPassword(ctx, "Test", "Enter password")

	if err == nil {
		t.Error("RequestPassword() expected error for invalid JSON, got nil")
	}
}

func TestGenerateCookie(t *testing.T) {
	cookie1, err := generateCookie()
	if err != nil {
		t.Fatalf("generateCookie() error = %v", err)
	}

	// Should be 32 hex characters (16 bytes)
	if len(cookie1) != 32 {
		t.Errorf("generateCookie() length = %d, want 32", len(cookie1))
	}

	// Each cookie should be unique
	cookie2, _ := generateCookie()
	if cookie1 == cookie2 {
		t.Error("generateCookie() produced duplicate cookies")
	}
}

func TestClient_ValidateSocket_RejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "real.sock")
	symlinkPath := filepath.Join(tmpDir, "link.sock")

	// Create real socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Create symlink pointing to the socket
	if err := os.Symlink(socketPath, symlinkPath); err != nil {
		t.Fatal(err)
	}

	client := NewClient(WithSocketPath(symlinkPath))
	err = client.ValidateSocket()

	if !errors.Is(err, ErrSocketSymlink) {
		t.Errorf("ValidateSocket() error = %v, want ErrSocketSymlink", err)
	}
}

func TestClient_ValidateSocket_RejectsWorldWritable(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Make socket world-writable
	if err := os.Chmod(socketPath, 0777); err != nil {
		t.Fatal(err)
	}

	client := NewClient(WithSocketPath(socketPath))
	err = client.ValidateSocket()

	if !errors.Is(err, ErrSocketPermissions) {
		t.Errorf("ValidateSocket() error = %v, want ErrSocketPermissions", err)
	}
}

func TestClient_ValidateSocket_RejectsGroupWritable(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Make socket group-writable
	if err := os.Chmod(socketPath, 0770); err != nil {
		t.Fatal(err)
	}

	client := NewClient(WithSocketPath(socketPath))
	err = client.ValidateSocket()

	if !errors.Is(err, ErrSocketPermissions) {
		t.Errorf("ValidateSocket() error = %v, want ErrSocketPermissions", err)
	}
}

func TestClient_ValidateSocket_RejectsBadParentDir(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0700); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(subDir, "test.sock")

	// Create socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Make parent directory world-writable
	if err := os.Chmod(subDir, 0777); err != nil {
		t.Fatal(err)
	}

	client := NewClient(WithSocketPath(socketPath))
	err = client.ValidateSocket()

	if !errors.Is(err, ErrSocketParentPerms) {
		t.Errorf("ValidateSocket() error = %v, want ErrSocketParentPerms", err)
	}
}

func TestClient_ValidateSocket_AcceptsValid(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create socket with safe permissions (user only)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Ensure socket has safe permissions
	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(WithSocketPath(socketPath))
	err = client.ValidateSocket()

	if err != nil {
		t.Errorf("ValidateSocket() unexpected error for valid socket: %v", err)
	}
}
