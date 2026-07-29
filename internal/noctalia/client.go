package noctalia

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

const (
	// DefaultExecutable is the Noctalia v5 command-line executable.
	DefaultExecutable = "noctalia"
	// DefaultPluginEntry is the Noctalia v5 plugin entry point.
	DefaultPluginEntry = "frap129/noctalia-bitwarden-keyring:service"
	// DefaultTimeout is the default timeout for Noctalia v5 password prompts.
	DefaultTimeout = 120 * time.Second
	commandTimeout = 5 * time.Second
)

// CommandRunner runs a Noctalia v5 command.
type CommandRunner func(context.Context, string, ...string) error

// Client provides Noctalia v5 prompt communication.
type Client struct {
	executable  string
	pluginEntry string
	timeout     time.Duration
	run         CommandRunner
}

// Option configures a Client.
type Option func(*Client)

// WithCommandRunner replaces the command runner, primarily for testing.
func WithCommandRunner(run CommandRunner) Option {
	return func(client *Client) {
		if run != nil {
			client.run = run
		}
	}
}

// WithTimeout sets the timeout for Noctalia v5 password prompts.
func WithTimeout(timeout time.Duration) Option {
	return func(client *Client) {
		client.timeout = timeout
	}
}

// NewClient creates a Noctalia v5 client.
func NewClient(opts ...Option) *Client {
	client := &Client{
		executable:  DefaultExecutable,
		pluginEntry: DefaultPluginEntry,
		timeout:     DefaultTimeout,
		run: func(ctx context.Context, name string, args ...string) error {
			return exec.CommandContext(ctx, name, args...).Run()
		},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(client)
		}
	}
	if client.timeout <= 0 {
		client.timeout = DefaultTimeout
	}
	return client
}

// PasswordSession represents an authenticated Noctalia v5 prompt bridge.
type PasswordSession struct {
	bridge    *promptBridge
	cookie    string
	timeout   time.Duration
	closeOnce sync.Once
}

// SendResult sends the unlock result to the Noctalia v5 plugin.
func (s *PasswordSession) SendResult(success bool, errMsg string, retry bool) error {
	if s == nil || s.bridge == nil {
		return ErrSessionClosed
	}

	result := KeyringResult{
		Type:    MessageTypeResult,
		ID:      s.cookie,
		Success: success,
		Error:   errMsg,
		Retry:   retry,
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	err := s.bridge.sendResult(ctx, result)
	cancel()
	if err != nil {
		_ = s.Close()
		return err
	}
	if success || !retry {
		_ = s.Close()
	}
	return nil
}

// WaitForRetry waits for the next password from the current Noctalia v5 prompt.
func (s *PasswordSession) WaitForRetry(ctx context.Context, timeout time.Duration) (string, error) {
	if s == nil || s.bridge == nil {
		return "", ErrSessionClosed
	}
	if timeout <= 0 {
		timeout = s.timeout
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	response, err := s.bridge.waitResponse(ctx, timeout)
	if err != nil {
		_ = s.Close()
		return "", err
	}
	if err := validateResponse(response, s.cookie); err != nil {
		_ = s.Close()
		return "", err
	}
	switch response.Result {
	case ResultOK:
		return response.Password, nil
	case ResultCancelled:
		_ = s.Close()
		return "", ErrCancelled
	default:
		_ = s.Close()
		return "", fmt.Errorf("%w: unexpected result", ErrProtocolError)
	}
}

// Close closes the authenticated Noctalia v5 prompt bridge.
func (s *PasswordSession) Close() error {
	if s == nil || s.bridge == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { err = s.bridge.Close() })
	return err
}

// RequestPasswordWithSession requests a password and returns a live retry session.
func (c *Client) RequestPasswordWithSession(ctx context.Context, title, message string) (string, *PasswordSession, error) {
	if err := bridgeContextError(ctx); err != nil {
		return "", nil, err
	}
	cookie, err := generateCookie()
	if err != nil {
		return "", nil, fmt.Errorf("%w: generate request cookie", ErrPluginUnavailable)
	}
	request := KeyringRequest{
		Type:    MessageTypeRequest,
		Cookie:  cookie,
		Title:   title,
		Message: message,
	}
	bridge, err := newPromptBridge(request)
	if err != nil {
		return "", nil, fmt.Errorf("%w: create prompt bridge", ErrPluginUnavailable)
	}
	if err := bridgeContextError(ctx); err != nil {
		_ = bridge.Close()
		return "", nil, err
	}

	commandCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	runErr := c.run(commandCtx, c.executable, "msg", "plugin", c.pluginEntry, "all", MessageTypeRequest, cookie)
	commandErr := commandCtx.Err()
	cancel()
	if runErr != nil || commandErr != nil {
		_ = bridge.Close()
		return "", nil, commandError(ctx, runErr, commandErr)
	}

	response, err := bridge.waitResponse(ctx, c.timeout)
	if err != nil {
		_ = bridge.Close()
		return "", nil, err
	}
	if err := validateResponse(response, cookie); err != nil {
		_ = bridge.Close()
		return "", nil, err
	}

	switch response.Result {
	case ResultOK:
		return response.Password, &PasswordSession{bridge: bridge, cookie: cookie, timeout: c.timeout}, nil
	case ResultCancelled:
		_ = bridge.Close()
		return "", nil, ErrCancelled
	case ResultConfirmed:
		_ = bridge.Close()
		return "", nil, ErrConfirmOnly
	default:
		_ = bridge.Close()
		return "", nil, fmt.Errorf("%w: unexpected result", ErrProtocolError)
	}
}

func validateResponse(response KeyringResponse, cookie string) error {
	if response.Type != MessageTypeResponse {
		return fmt.Errorf("%w: unexpected response type", ErrProtocolError)
	}
	if response.ID != cookie {
		return ErrCookieMismatch
	}
	switch response.Result {
	case ResultOK:
		if response.Password == "" {
			return fmt.Errorf("%w: empty password", ErrProtocolError)
		}
	case ResultCancelled, ResultConfirmed:
		if response.Password != "" {
			return fmt.Errorf("%w: unexpected password", ErrProtocolError)
		}
	default:
		return fmt.Errorf("%w: unexpected result", ErrProtocolError)
	}
	return nil
}

func commandError(parent context.Context, runErr, commandErr error) error {
	if errors.Is(parent.Err(), context.DeadlineExceeded) || errors.Is(commandErr, context.DeadlineExceeded) || errors.Is(runErr, context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(parent.Err(), context.Canceled) {
		return ErrCancelled
	}
	return fmt.Errorf("%w: plugin command failed", ErrPluginUnavailable)
}

func generateCookie() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// RequestPassword requests a password and closes its session before returning.
func (c *Client) RequestPassword(ctx context.Context, title, message string) (string, error) {
	password, session, err := c.RequestPasswordWithSession(ctx, title, message)
	if err != nil {
		return "", err
	}
	_ = session.Close()
	return password, nil
}
