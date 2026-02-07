package noctalia

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultSocketName is the default socket filename for the Noctalia Quickshell plugin
	DefaultSocketName = "noctalia-keyring.sock"

	// DefaultTimeout is the default timeout for password prompts (2 minutes)
	DefaultTimeout = 120 * time.Second

	// connectTimeout is the timeout for establishing the socket connection
	connectTimeout = 5 * time.Second
)

// Client provides IPC communication with the Noctalia Quickshell plugin
type Client struct {
	socketPath string
	timeout    time.Duration
}

// Option configures a Client
type Option func(*Client)

// WithSocketPath sets a custom socket path
func WithSocketPath(path string) Option {
	return func(c *Client) {
		c.socketPath = path
	}
}

// WithTimeout sets a custom timeout for password prompts
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// NewClient creates a new Noctalia IPC client
func NewClient(opts ...Option) *Client {
	c := &Client{
		socketPath: defaultSocketPath(),
		timeout:    DefaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// defaultSocketPath returns the default socket path based on XDG_RUNTIME_DIR
func defaultSocketPath() string {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		// Fallback to /run/user/<uid>
		runtimeDir = filepath.Join("/run/user", fmt.Sprintf("%d", os.Getuid()))
	}
	return filepath.Join(runtimeDir, DefaultSocketName)
}

// IsAvailable checks if the Noctalia agent socket exists and is accessible
func (c *Client) IsAvailable() bool {
	return c.ValidateSocket() == nil
}

// ValidateSocket validates that the socket exists and has secure permissions.
// It checks:
// - Socket is not a symbolic link
// - Path is actually a socket
// - Socket is owned by the current user
// - Socket is not group or world writable
// - Parent directory is owned by current user and not group/world writable
func (c *Client) ValidateSocket() error {
	// Use Lstat to detect symlinks (doesn't follow them)
	info, err := os.Lstat(c.socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrSocketNotFound
		}
		return fmt.Errorf("failed to stat socket: %w", err)
	}

	// Reject symbolic links
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrSocketSymlink
	}

	// Verify it's actually a socket
	if info.Mode()&os.ModeSocket == 0 {
		return ErrSocketNotSocket
	}

	// Get the underlying syscall stat to check UID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get socket stat info")
	}

	// Verify socket is owned by current user
	currentUID := uint32(os.Getuid())
	if stat.Uid != currentUID {
		return ErrSocketOwner
	}

	// Check socket permissions - reject group or world writable
	mode := info.Mode().Perm()
	if mode&0022 != 0 { // Check group-write (020) and world-write (002) bits
		return ErrSocketPermissions
	}

	// Validate parent directory
	parentDir := filepath.Dir(c.socketPath)
	parentInfo, err := os.Lstat(parentDir)
	if err != nil {
		return fmt.Errorf("failed to stat parent directory: %w", err)
	}

	// Get parent directory stat
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get parent directory stat info")
	}

	// Verify parent directory is owned by current user
	if parentStat.Uid != currentUID {
		return ErrSocketParentOwner
	}

	// Check parent directory permissions - reject group or world writable
	parentMode := parentInfo.Mode().Perm()
	if parentMode&0022 != 0 {
		return ErrSocketParentPerms
	}

	return nil
}

// SocketPath returns the configured socket path
func (c *Client) SocketPath() string {
	return c.socketPath
}

// PasswordSession represents an active password prompt session with the Noctalia plugin.
// It keeps the connection open to enable two-phase communication for password retry support.
type PasswordSession struct {
	conn   net.Conn
	cookie string
	closed bool
	mu     sync.Mutex
}

// SendResult sends the unlock result back to the plugin.
// This should be called after attempting to unlock the vault with the password.
// If success is true, the plugin will close the dialog.
// If success is false and retry is true, the plugin will show the error and allow retry.
// The session is automatically closed after sending the result.
func (s *PasswordSession) SendResult(success bool, errMsg string, retry bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("session already closed")
	}

	result := KeyringResult{
		Type:    MessageTypeResult,
		ID:      s.cookie,
		Success: success,
		Error:   errMsg,
		Retry:   retry,
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		s.close()
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	resultBytes = append(resultBytes, '\n')

	// Set a write deadline to avoid blocking forever
	if err := s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		s.close()
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := s.conn.Write(resultBytes); err != nil {
		s.close()
		return fmt.Errorf("failed to send result: %w", err)
	}

	// Close after sending success result, keep open for retry
	if success || !retry {
		s.close()
	}

	return nil
}

// WaitForRetry waits for the user to submit a new password after a failed attempt.
// This should only be called after SendResult(false, errMsg, true).
// Returns the new password or an error if the user cancels or times out.
func (s *PasswordSession) WaitForRetry(ctx context.Context, timeout time.Duration) (string, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", errors.New("session already closed")
	}
	conn := s.conn
	cookie := s.cookie
	s.mu.Unlock()

	// Set read deadline
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Wait for response with context cancellation support
	reader := bufio.NewReader(conn)
	respLine, err := readWithContext(ctx, conn, reader)
	if err != nil {
		s.Close()
		if errors.Is(err, context.Canceled) {
			return "", ErrCancelled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "", ErrTimeout
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", ErrTimeout
		}
		if errors.Is(err, io.EOF) {
			return "", ErrCancelled
		}
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var resp KeyringResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		s.Close()
		return "", fmt.Errorf("%w: invalid JSON response: %v", ErrProtocolError, err)
	}

	// Validate response
	if resp.Type != MessageTypeResponse {
		s.Close()
		return "", fmt.Errorf("%w: unexpected response type: %s", ErrProtocolError, resp.Type)
	}

	if resp.ID != cookie {
		s.Close()
		return "", fmt.Errorf("%w: expected %s, got %s", ErrCookieMismatch, cookie, resp.ID)
	}

	switch resp.Result {
	case ResultOK:
		return resp.Password, nil
	case ResultCancelled:
		s.Close()
		return "", ErrCancelled
	default:
		s.Close()
		return "", fmt.Errorf("%w: unknown result: %s", ErrProtocolError, resp.Result)
	}
}

// Close closes the session connection.
func (s *PasswordSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.close()
}

// close closes the connection (must be called with lock held)
func (s *PasswordSession) close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.conn.Close()
}

// RequestPasswordWithSession sends a password request to the Noctalia agent and returns
// a session that can be used to send unlock results and handle retries.
// The caller must close the session when done.
func (c *Client) RequestPasswordWithSession(ctx context.Context, title, message string) (string, *PasswordSession, error) {
	// Validate socket security before attempting connection
	if err := c.ValidateSocket(); err != nil {
		return "", nil, err
	}

	// Generate unique cookie for this request
	cookie, err := generateCookie()
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate cookie: %w", err)
	}

	// Create request
	req := KeyringRequest{
		Type:        MessageTypeRequest,
		Cookie:      cookie,
		Title:       title,
		Message:     message,
		Description: "",
		PasswordNew: false,
		ConfirmOnly: false,
	}

	// Connect to socket with timeout
	dialer := net.Dialer{Timeout: connectTimeout}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "", nil, ErrCancelled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "", nil, ErrTimeout
		}
		return "", nil, fmt.Errorf("%w: %w", ErrConnectionFailed, err)
	}

	// Set read deadline based on timeout
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		conn.Close()
		return "", nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Send request as newline-delimited JSON
	reqBytes, err := json.Marshal(req)
	if err != nil {
		conn.Close()
		return "", nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')

	if _, err := conn.Write(reqBytes); err != nil {
		conn.Close()
		return "", nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response with context cancellation support
	reader := bufio.NewReader(conn)
	respLine, err := readWithContext(ctx, conn, reader)
	if err != nil {
		conn.Close()
		if errors.Is(err, context.Canceled) {
			return "", nil, ErrCancelled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return "", nil, ErrTimeout
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", nil, ErrTimeout
		}
		// Connection closed without response = user cancelled (closed the window)
		if errors.Is(err, io.EOF) {
			return "", nil, ErrCancelled
		}
		return "", nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var resp KeyringResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		conn.Close()
		return "", nil, fmt.Errorf("%w: invalid JSON response: %v", ErrProtocolError, err)
	}

	// Validate response type
	if resp.Type != MessageTypeResponse {
		conn.Close()
		return "", nil, fmt.Errorf("%w: unexpected response type: %s", ErrProtocolError, resp.Type)
	}

	// Validate cookie matches
	if resp.ID != cookie {
		conn.Close()
		return "", nil, fmt.Errorf("%w: expected %s, got %s", ErrCookieMismatch, cookie, resp.ID)
	}

	// Create session to keep connection open
	session := &PasswordSession{
		conn:   conn,
		cookie: cookie,
	}

	// Handle result
	switch resp.Result {
	case ResultOK:
		return resp.Password, session, nil
	case ResultCancelled:
		session.Close()
		return "", nil, ErrCancelled
	case ResultConfirmed:
		session.Close()
		return "", nil, ErrConfirmOnly
	default:
		session.Close()
		return "", nil, fmt.Errorf("%w: unknown result: %s", ErrProtocolError, resp.Result)
	}
}

// readWithContext reads from the connection with context cancellation support.
// It uses a goroutine to read and monitors the context's Done channel.
func readWithContext(ctx context.Context, conn net.Conn, reader *bufio.Reader) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}

	resultChan := make(chan result, 1)

	// Start reading in a goroutine
	go func() {
		data, err := reader.ReadBytes('\n')
		resultChan <- result{data: data, err: err}
	}()

	select {
	case <-ctx.Done():
		// Context was cancelled - close connection to unblock read
		_ = conn.SetReadDeadline(time.Now()) // best-effort unblock
		_ = conn.Close()
		select {
		case <-resultChan:
		case <-time.After(1 * time.Second):
			// give up joining; avoid deadlock
		}
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.data, res.err
	}
}

// generateCookie generates a unique request ID using 16 random bytes
// encoded as a 32-character hex string
func generateCookie() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RequestPassword is a convenience wrapper that requests a password without session support.
// For retry support, use RequestPasswordWithSession instead.
func (c *Client) RequestPassword(ctx context.Context, title, message string) (string, error) {
	password, session, err := c.RequestPasswordWithSession(ctx, title, message)
	if err != nil {
		return "", err
	}
	// Close session immediately since caller doesn't need it
	session.Close()
	return password, nil
}
