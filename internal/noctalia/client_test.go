// Package noctalia provides an IPC client for the Noctalia Quickshell plugin
// to enable Noctalia UI integration for password prompts.
package noctalia

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
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

// MultiPhaseSession tracks a multi-phase authentication session
// for testing retry flows
type MultiPhaseSession struct {
	mu      sync.Mutex
	cookie  string
	phase   int
	results []KeyringResult
}

func (s *MultiPhaseSession) GetResults() []KeyringResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	resultCopy := make([]KeyringResult, len(s.results))
	copy(resultCopy, s.results)
	return resultCopy
}

// MultiPhaseMockServer is a mock server that supports multi-phase authentication
// sessions for testing retry flows
type MultiPhaseMockServer struct {
	listener   net.Listener
	socketPath string
	sessions   map[string]*MultiPhaseSession
	sessionsMu sync.RWMutex
	script     []MockServerAction
	scriptMu   sync.RWMutex
	done       chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
	connsMu    sync.Mutex
	conns      map[net.Conn]struct{}
}

// MockServerAction represents an action the mock server should take
type MockServerAction struct {
	Phase       int
	Response    *KeyringResponse
	Delay       time.Duration
	CloseConn   bool
	WrongCookie bool
}

// NewMultiPhaseMockServer creates a mock server that supports multi-phase sessions
func NewMultiPhaseMockServer(t *testing.T, socketPath string) *MultiPhaseMockServer {
	t.Helper()

	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to create multi-phase mock server: %v", err)
	}

	m := &MultiPhaseMockServer{
		listener:   listener,
		socketPath: socketPath,
		sessions:   make(map[string]*MultiPhaseSession),
		done:       make(chan struct{}),
		conns:      make(map[net.Conn]struct{}),
	}

	m.wg.Add(1)
	go m.acceptLoop(t)

	t.Cleanup(m.Close)

	return m
}

func (m *MultiPhaseMockServer) acceptLoop(t *testing.T) {
	defer m.wg.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.done:
				return
			default:
				return
			}
		}

		m.connsMu.Lock()
		m.conns[conn] = struct{}{}
		m.connsMu.Unlock()

		m.wg.Add(1)
		go func(c net.Conn) {
			defer m.wg.Done()
			m.handleConnection(t, c)
			m.connsMu.Lock()
			delete(m.conns, c)
			m.connsMu.Unlock()
		}(conn)
	}
}

func (m *MultiPhaseMockServer) handleConnection(t *testing.T, conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		// Set read deadline for the connection
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				select {
				case <-m.done:
					return
				default:
					t.Logf("Multi-phase mock server: failed to read: %v", err)
				}
			}
			return
		}

		// Try to parse as KeyringRequest (initial request)
		var req KeyringRequest
		if err := json.Unmarshal(line, &req); err == nil && req.Type == MessageTypeRequest {
			m.handleRequest(t, conn, &req)
			continue
		}

		// Try to parse as KeyringResult (subsequent results)
		var result KeyringResult
		if err := json.Unmarshal(line, &result); err == nil && result.Type == MessageTypeResult {
			m.handleResult(t, conn, &result)
			continue
		}

		select {
		case <-m.done:
			return
		default:
			t.Logf("Multi-phase mock server: unknown message: %s", string(line))
		}
	}
}

func (m *MultiPhaseMockServer) handleRequest(t *testing.T, conn net.Conn, req *KeyringRequest) {
	m.sessionsMu.Lock()

	// Create or get session
	session, exists := m.sessions[req.Cookie]
	if !exists {
		session = &MultiPhaseSession{
			cookie: req.Cookie,
			phase:  0,
		}
		m.sessions[req.Cookie] = session
	}

	phase := session.phase
	session.phase++

	// Get action from script if available
	action := m.getActionForPhase(phase)
	m.sessionsMu.Unlock()

	// Apply delay if specified
	if action.Delay > 0 {
		time.Sleep(action.Delay)
	}

	// Send response
	var resp KeyringResponse
	if action.Response != nil {
		resp = *action.Response
		if action.WrongCookie {
			resp.ID = "wrong-cookie-12345"
		} else if resp.ID == "" {
			resp.ID = req.Cookie
		}
	} else {
		resp = KeyringResponse{
			Type:   MessageTypeResponse,
			ID:     req.Cookie,
			Result: ResultOK,
		}
	}

	respBytes, _ := json.Marshal(resp)
	respBytes = append(respBytes, '\n')
	conn.Write(respBytes)

	if action.CloseConn {
		conn.Close()
	}
}

func (m *MultiPhaseMockServer) handleResult(t *testing.T, conn net.Conn, result *KeyringResult) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	session, exists := m.sessions[result.ID]
	if !exists {
		select {
		case <-m.done:
			return
		default:
			t.Logf("Multi-phase mock server: received result for unknown session: %s", result.ID)
			return
		}
	}

	session.mu.Lock()
	session.results = append(session.results, *result)
	phase := session.phase
	session.phase++
	session.mu.Unlock()

	// Check if we should send a retry response
	action := m.getActionForPhase(phase)
	if action.Response != nil {
		// Apply delay if specified
		if action.Delay > 0 {
			time.Sleep(action.Delay)
		}

		resp := *action.Response
		if action.WrongCookie {
			resp.ID = "wrong-cookie-12345"
		} else if resp.ID == "" {
			resp.ID = result.ID
		}

		respBytes, _ := json.Marshal(resp)
		respBytes = append(respBytes, '\n')
		conn.Write(respBytes)

		if action.CloseConn {
			conn.Close()
		}
	} else if !result.Success {
		// Default behavior: if not successful and no action defined, delete session
		delete(m.sessions, result.ID)
	} else {
		// Success - delete session
		delete(m.sessions, result.ID)
	}
}

func (m *MultiPhaseMockServer) getActionForPhase(phase int) MockServerAction {
	m.scriptMu.RLock()
	defer m.scriptMu.RUnlock()

	for _, action := range m.script {
		if action.Phase == phase {
			return action
		}
	}
	return MockServerAction{Phase: phase}
}

// SetScript configures the sequence of actions for multi-phase sessions
func (m *MultiPhaseMockServer) SetScript(actions []MockServerAction) {
	m.scriptMu.Lock()
	defer m.scriptMu.Unlock()
	m.script = actions
}

// GetSession returns a session by cookie
func (m *MultiPhaseMockServer) GetSession(cookie string) (*MultiPhaseSession, bool) {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	session, ok := m.sessions[cookie]
	return session, ok
}

// Close shuts down the multi-phase mock server
func (m *MultiPhaseMockServer) Close() {
	m.closeOnce.Do(func() {
		close(m.done)
		m.listener.Close()

		// Close all tracked connections
		m.connsMu.Lock()
		for conn := range m.conns {
			conn.Close()
		}
		m.connsMu.Unlock()

		// Wait for all goroutines to finish
		m.wg.Wait()

		os.Remove(m.socketPath)
	})
}

// GetResults returns the results received for a session
func (m *MultiPhaseMockServer) GetResults(cookie string) []KeyringResult {
	m.sessionsMu.RLock()
	session, exists := m.sessions[cookie]
	m.sessionsMu.RUnlock()
	if !exists {
		return nil
	}
	return session.GetResults()
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

// TestClient_FullRetryCycle tests the complete retry flow:
// prompt → wrong password → retry → correct password → dismiss
func TestClient_FullRetryCycle(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMultiPhaseMockServer(t, socketPath)
	defer server.Close()

	// Set up the script for the full retry cycle:
	// Phase 0: Initial prompt → return wrong password
	// Phase 1: After wrong password result → send retry with correct password
	// Phase 2: After correct password result → close/dismiss
	server.SetScript([]MockServerAction{
		{
			Phase: 0,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "wrong-password",
			},
		},
		{
			Phase: 1,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "correct-password",
			},
		},
	})

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	ctx := context.Background()

	// Step 1: Request password with session
	password, session, err := client.RequestPasswordWithSession(ctx, "Test Title", "Enter password")
	if err != nil {
		t.Fatalf("RequestPasswordWithSession() error = %v", err)
	}
	defer session.Close()

	// Should get the wrong password first
	if password != "wrong-password" {
		t.Errorf("First password = %q, want %q", password, "wrong-password")
	}

	// Step 2: Send result indicating failure but allowing retry
	err = session.SendResult(false, "Invalid password", true)
	if err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}

	// Step 3: Wait for retry - should get the correct password
	retryPassword, err := session.WaitForRetry(ctx, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForRetry() error = %v", err)
	}

	if retryPassword != "correct-password" {
		t.Errorf("Retry password = %q, want %q", retryPassword, "correct-password")
	}

	// Step 4: Send success result
	err = session.SendResult(true, "", false)
	if err != nil {
		t.Fatalf("SendResult(success) error = %v", err)
	}

	// Verify we got the results
	// Note: We can't easily verify the results on the server side without
	// additional synchronization, but we verified the flow works
}

// TestClient_WaitForRetry_Timeout tests that WaitForRetry respects context deadline
func TestClient_WaitForRetry_Timeout(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMultiPhaseMockServer(t, socketPath)
	defer server.Close()

	// Set up script: respond immediately to initial request, but delay retry response
	server.SetScript([]MockServerAction{
		{
			Phase: 0,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "first-password",
			},
		},
		{
			Phase:    1,
			Delay:    2 * time.Second, // Delay beyond context timeout
			Response: nil,             // Don't send - let it timeout
		},
	})

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	ctx := context.Background()

	// Get initial password
	password, session, err := client.RequestPasswordWithSession(ctx, "Test", "Enter password")
	if err != nil {
		t.Fatalf("RequestPasswordWithSession() error = %v", err)
	}
	defer session.Close()

	if password != "first-password" {
		t.Errorf("Password = %q, want %q", password, "first-password")
	}

	// Send result with retry
	err = session.SendResult(false, "Try again", true)
	if err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}

	// Create context with short timeout for WaitForRetry
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// WaitForRetry should timeout
	_, err = session.WaitForRetry(ctxTimeout, 5*time.Second)
	if err != ErrTimeout && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("WaitForRetry() error = %v, want ErrTimeout or context.DeadlineExceeded", err)
	}
}

// TestClient_CookieMismatch tests that cookie mismatch is detected
func TestClient_CookieMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMultiPhaseMockServer(t, socketPath)
	defer server.Close()

	// Set up script: send wrong cookie in retry response
	server.SetScript([]MockServerAction{
		{
			Phase: 0,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "first-password",
			},
		},
		{
			Phase:       1,
			WrongCookie: true,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "retry-password",
			},
		},
	})

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	ctx := context.Background()

	// Get initial password
	password, session, err := client.RequestPasswordWithSession(ctx, "Test", "Enter password")
	if err != nil {
		t.Fatalf("RequestPasswordWithSession() error = %v", err)
	}
	defer session.Close()

	if password != "first-password" {
		t.Errorf("Password = %q, want %q", password, "first-password")
	}

	// Send result with retry
	err = session.SendResult(false, "Try again", true)
	if err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}

	// WaitForRetry should detect cookie mismatch
	_, err = session.WaitForRetry(ctx, 5*time.Second)
	if !errors.Is(err, ErrCookieMismatch) {
		t.Errorf("WaitForRetry() error = %v, want ErrCookieMismatch", err)
	}
}

// TestClient_ContextCancelled tests that context cancellation works during PromptPassword
func TestClient_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMultiPhaseMockServer(t, socketPath)
	defer server.Close()

	// Set up script: delay the response so we can cancel first
	server.SetScript([]MockServerAction{
		{
			Phase: 0,
			Delay: 2 * time.Second,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "password123",
			},
		},
	})

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(5*time.Second),
	)

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// RequestPassword should return cancelled error when context is cancelled
	_, err := client.RequestPassword(ctx, "Test", "Enter password")
	if err == nil {
		t.Fatal("RequestPassword() expected error, got nil")
	}

	// The error should be ErrCancelled when context is cancelled
	if !errors.Is(err, ErrCancelled) {
		t.Errorf("RequestPassword() error = %v, want ErrCancelled", err)
	}
}

// TestClient_WaitForRetry_ContextCancelled tests context cancellation during WaitForRetry
func TestClient_WaitForRetry_ContextCancelled(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	server := NewMultiPhaseMockServer(t, socketPath)
	defer server.Close()

	// Set up script: respond to initial request, but don't respond to retry
	server.SetScript([]MockServerAction{
		{
			Phase: 0,
			Response: &KeyringResponse{
				Type:     MessageTypeResponse,
				Result:   ResultOK,
				Password: "first-password",
			},
		},
		{
			Phase:    1,
			Delay:    5 * time.Second, // Long delay
			Response: nil,
		},
	})

	client := NewClient(
		WithSocketPath(socketPath),
		WithTimeout(10*time.Second),
	)

	ctx := context.Background()

	// Get initial password
	password, session, err := client.RequestPasswordWithSession(ctx, "Test", "Enter password")
	if err != nil {
		t.Fatalf("RequestPasswordWithSession() error = %v", err)
	}
	defer session.Close()

	if password != "first-password" {
		t.Errorf("Password = %q, want %q", password, "first-password")
	}

	// Send result with retry
	err = session.SendResult(false, "Try again", true)
	if err != nil {
		t.Fatalf("SendResult() error = %v", err)
	}

	// Create cancellable context for WaitForRetry
	ctxRetry, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	// WaitForRetry should return ErrCancelled when context is cancelled
	_, err = session.WaitForRetry(ctxRetry, 10*time.Second)
	if err == nil {
		t.Fatal("WaitForRetry() expected error after context cancellation")
	}

	// Should return ErrCancelled when context is cancelled
	if !errors.Is(err, ErrCancelled) {
		t.Errorf("WaitForRetry() error = %v, want ErrCancelled", err)
	}
}
