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

// RequestPassword sends a password request to the Noctalia agent and waits for
// the user to enter their password. The connection is kept open until a response
// is received or the context is cancelled.
func (c *Client) RequestPassword(ctx context.Context, title, message string) (string, error) {
	// Validate socket security before attempting connection
	if err := c.ValidateSocket(); err != nil {
		return "", err
	}

	// Generate unique cookie for this request
	cookie, err := generateCookie()
	if err != nil {
		return "", fmt.Errorf("failed to generate cookie: %w", err)
	}

	// Create request
	req := KeyringRequest{
		Type:        "keyring_request",
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
		return "", fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer conn.Close()

	// Set read deadline based on timeout
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return "", fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Send request as newline-delimited JSON
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	reqBytes = append(reqBytes, '\n')

	if _, err := conn.Write(reqBytes); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response (blocking read, connection stays open)
	reader := bufio.NewReader(conn)
	respLine, err := reader.ReadBytes('\n')
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", ErrTimeout
		}
		// Connection closed without response = user cancelled (closed the window)
		if errors.Is(err, io.EOF) {
			return "", ErrCancelled
		}
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var resp KeyringResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return "", fmt.Errorf("%w: invalid JSON response: %v", ErrProtocolError, err)
	}

	// Validate response type
	if resp.Type != "keyring_response" {
		return "", fmt.Errorf("%w: unexpected response type: %s", ErrProtocolError, resp.Type)
	}

	// Validate cookie matches
	if resp.ID != cookie {
		return "", fmt.Errorf("%w: expected %s, got %s", ErrCookieMismatch, cookie, resp.ID)
	}

	// Handle result
	switch resp.Result {
	case ResultOK:
		return resp.Password, nil
	case ResultCancelled:
		return "", ErrCancelled
	case ResultConfirmed:
		return "", ErrConfirmOnly
	default:
		return "", fmt.Errorf("%w: unknown result: %s", ErrProtocolError, resp.Result)
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
