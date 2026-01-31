package bitwarden

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// jsonBody marshals v to JSON and returns a reader for HTTP request bodies.
// This is a convenience helper to avoid repeated json.Marshal + bytes.NewReader patterns.
func jsonBody(v interface{}) (io.Reader, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// decodeJSON reads JSON from r into v with a descriptive error message.
func decodeJSON(r io.Reader, v interface{}, what string) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return fmt.Errorf("failed to decode %s: %w", what, err)
	}
	return nil
}

// APIError represents a sanitized API error that never leaks HTTP response bodies.
// Use DebugDetails() to access the body for logging when debug mode is enabled.
type APIError struct {
	StatusCode int
	Path       string
	debugBody  string // never exposed in Error()
}

// Error returns a safe error message without leaking the HTTP response body.
func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d on %s", e.StatusCode, e.Path)
}

// DebugDetails returns the HTTP response body for debug logging.
func (e *APIError) DebugDetails() string {
	return e.debugBody
}

// passwordPrompter provides a way to prompt for passwords.
// It is implemented by SessionManager and can be overridden in tests.
type passwordPrompter interface {
	PromptForPassword() (string, error)
}

// logHTTPBodySnippet returns a truncated and redacted snippet of an HTTP body for debug logging.
// It truncates to at most 512 bytes total (including truncation marker and prefix) and redacts sensitive fields
// like password, token, etc. The prefix is prepended to the output for context.
func logHTTPBodySnippet(prefix, body string) string {
	const maxLen = 512
	const truncationMarker = "[truncated...]"

	// Account for prefix and separator in total length
	prefixLen := len(prefix) + len(": ")
	maxBodyLen := maxLen - prefixLen

	// Truncate if needed, accounting for the marker
	if len(body) > maxBodyLen {
		// Leave room for the truncation marker
		availableLen := maxBodyLen - len(truncationMarker)
		if availableLen > 0 {
			body = body[:availableLen] + truncationMarker
		} else {
			body = truncationMarker
		}
	}

	// Redact sensitive patterns: password, raw, token, session, authorization, key
	redactionPattern := regexp.MustCompile(`(?i)"(password|raw|token|session|authorization|key)"\s*:\s*"([^"]*)"`)
	redacted := redactionPattern.ReplaceAllString(body, `"$1":"[redacted]"`)

	return prefix + ": " + redacted
}

// Client provides access to the Bitwarden CLI REST API
type Client struct {
	baseURL    string
	httpClient *http.Client
	session    *SessionManager
	mu         sync.RWMutex
	serveCmd   *exec.Cmd
	serveDone  chan error // closed/sent when Wait() returns
	serveErr   error      // last exit error
	servePID   int        // process ID
	unlockMu   sync.Mutex
	autoUnlock atomic.Bool
	debug      atomic.Bool
	prompter   passwordPrompter // used for password prompting; defaults to session
}

// NewClient creates a new Bitwarden API client
func NewClient(port int) *Client {
	return NewClientWithConfig(port, DefaultSessionConfig())
}

// NewClientWithConfig creates a new Bitwarden API client with custom session config
func NewClientWithConfig(port int, sessionCfg SessionConfig) *Client {
	c := &Client{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		session: NewSessionManagerWithConfig(sessionCfg),
	}
	c.autoUnlock.Store(true)
	c.prompter = c.session
	return c
}

// SetAutoUnlock enables or disables automatic unlocking with password prompt.
// When disabled, operations that require an unlocked vault will return ErrVaultLocked.
// This is useful for testing or programmatic control.
func (c *Client) SetAutoUnlock(enabled bool) {
	c.autoUnlock.Store(enabled)
}

// SetDebug enables or disables HTTP body logging for errors.
// When enabled, APIError.DebugDetails() will contain response bodies (up to 4096 bytes),
// which are redacted but should only be logged with --debug flag.
func (c *Client) SetDebug(enabled bool) {
	c.debug.Store(enabled)
}

// StartServe starts the 'bw serve' process if not already running
func (c *Client) StartServe(ctx context.Context, port int) error {
	c.mu.Lock()

	// Check if already running
	if c.serveCmd != nil && c.serveCmd.Process != nil {
		c.mu.Unlock()
		return nil
	}

	// Check if bw is available
	if _, err := exec.LookPath("bw"); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("bitwarden CLI (bw) not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, "bw", "serve", "--hostname", "127.0.0.1", "--port", fmt.Sprintf("%d", port))

	// Pass through session key if available
	sessionKey := c.session.GetSession()
	if sessionKey != "" {
		cmd.Env = append(os.Environ(), "BW_SESSION="+sessionKey)
	}

	if err := cmd.Start(); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to start bw serve: %w", err)
	}

	c.serveCmd = cmd
	c.servePID = cmd.Process.Pid
	c.serveDone = make(chan error, 1)
	c.serveErr = nil

	// Unlock before waitForReady (which makes HTTP calls)
	c.mu.Unlock()

	// Spawn goroutine to wait for process exit
	go func() {
		err := cmd.Wait()
		c.mu.Lock()
		c.serveErr = err
		c.serveCmd = nil
		c.servePID = 0
		c.mu.Unlock()
		c.serveDone <- err
	}()

	// Wait for server to be ready
	if err := c.waitForReady(ctx); err != nil {
		// Readiness failed - stop the process to prevent zombies
		_ = c.Stop()
		return err
	}

	return nil
}

// ServeHealthy returns an error if the bw serve process is not healthy.
// It checks if the process was never started, has exited, or failed readiness.
func (c *Client) ServeHealthy() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check if serve was never started
	if c.serveCmd == nil && c.servePID == 0 && c.serveDone == nil {
		return fmt.Errorf("bw serve not started")
	}

	// Check if process has exited
	if c.serveErr != nil {
		return fmt.Errorf("bw serve process exited: %w", c.serveErr)
	}

	// Check if process is nil (may have been stopped)
	if c.serveCmd == nil {
		return fmt.Errorf("bw serve process not running")
	}

	return nil
}

// waitForReady waits for the bw serve API to be responsive
func (c *Client) waitForReady(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_, err := c.Status(ctx)
			if err == nil {
				return nil
			}
		}
	}
}

// Stop stops the bw serve process gracefully with SIGTERM, then SIGKILL if needed.
// Always waits for the process to exit (reaps zombie).
func (c *Client) Stop() error {
	c.mu.Lock()
	cmd := c.serveCmd
	done := c.serveDone
	pid := c.servePID
	c.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// Send SIGTERM
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// Process may already be dead
		if done != nil {
			select {
			case <-done:
				return nil
			default:
			}
		}
	}

	// Wait up to 3 seconds for graceful shutdown
	select {
	case <-done:
		// Process exited gracefully
		return nil
	case <-time.After(3 * time.Second):
		// Timeout - send SIGKILL
	}

	// Send SIGKILL
	if err := cmd.Process.Kill(); err != nil {
		// Process may already be dead
		if done != nil {
			select {
			case <-done:
				return nil
			default:
			}
		}
	}

	// Wait up to 1 second for SIGKILL to take effect
	select {
	case <-done:
		return nil
	case <-time.After(1 * time.Second):
		return fmt.Errorf("process %d did not exit after SIGKILL", pid)
	}
}

// Status returns the current vault status
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status StatusResponse
	if err := decodeJSON(resp.Body, &status, "status response"); err != nil {
		return nil, err
	}

	return &status, nil
}

// IsLocked returns whether the vault is currently locked
func (c *Client) IsLocked(ctx context.Context) (bool, error) {
	status, err := c.Status(ctx)
	if err != nil {
		return true, err
	}
	return status.Data.Template.Status == "locked", nil
}

// IsLockedSafe returns whether the vault is currently locked, defaulting to true on error.
// This is useful for D-Bus property getters that should return a safe default rather than
// surfacing errors. Do not use this where errors should be propagated (e.g., in operations
// that need to know the precise lock state before proceeding).
func (c *Client) IsLockedSafe(ctx context.Context) bool {
	locked, err := c.IsLocked(ctx)
	if err != nil {
		return true // Safe default: assume locked on error
	}
	return locked
}

// Unlock unlocks the vault with the provided password
func (c *Client) Unlock(ctx context.Context, password string) (string, error) {
	body, err := jsonBody(UnlockRequest{Password: password})
	if err != nil {
		return "", err
	}

	resp, err := c.doRequest(ctx, "POST", "/unlock", body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result UnlockResponse
	if err := decodeJSON(resp.Body, &result, "unlock response"); err != nil {
		return "", err
	}

	if !result.Success {
		return "", fmt.Errorf("unlock failed: %s", result.Data.Message)
	}

	// Store the session key
	c.session.SetSession(result.Data.Raw)

	return result.Data.Raw, nil
}

// Lock locks the vault
func (c *Client) Lock(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "POST", "/lock", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.session.ClearSession()
	return nil
}

// ensureUnlocked checks if the vault is locked and prompts for unlock if needed.
// Only prompts if autoUnlock is true. Returns ErrVaultLocked if autoUnlock is false.
// Uses double-check locking to prevent concurrent password prompts.
func (c *Client) ensureUnlocked(ctx context.Context) error {
	if !c.autoUnlock.Load() {
		locked, err := c.IsLocked(ctx)
		if err != nil {
			return fmt.Errorf("failed to check vault status: %w", err)
		}
		if locked {
			return ErrVaultLocked
		}
		return nil
	}

	// Quick check without lock
	locked, err := c.IsLocked(ctx)
	if err != nil {
		return fmt.Errorf("failed to check vault status: %w", err)
	}
	if !locked {
		return nil
	}

	// Check context before waiting on lock
	if err := ctx.Err(); err != nil {
		return err
	}

	// Serialize unlock attempts
	c.unlockMu.Lock()
	defer c.unlockMu.Unlock()

	// Check context after acquiring lock (may have waited)
	if err := ctx.Err(); err != nil {
		return err
	}

	// Re-check after acquiring lock (another goroutine may have unlocked)
	locked, err = c.IsLocked(ctx)
	if err != nil {
		return fmt.Errorf("failed to check vault status: %w", err)
	}
	if !locked {
		return nil
	}

	// Check if serve is healthy before prompting for password
	if err := c.ServeHealthy(); err != nil {
		return fmt.Errorf("backend not healthy: %w", err)
	}

	// Prompt for password (note: not cancellable)
	password, err := c.prompter.PromptForPassword()
	if err != nil {
		return err // Preserves ErrUserCancelled
	}

	// Unlock the vault
	if _, err := c.Unlock(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	return nil
}

// withAutoUnlock wraps an operation with auto-unlock logic
func (c *Client) withAutoUnlock(ctx context.Context, fn func() error) error {
	if err := c.ensureUnlocked(ctx); err != nil {
		return err
	}
	return fn()
}

// Sync synchronizes the vault with the server
func (c *Client) Sync(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "POST", "/sync", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// listItemsInternal performs the actual ListItems API call
func (c *Client) listItemsInternal(ctx context.Context) ([]Item, error) {
	resp, err := c.doRequest(ctx, "GET", "/list/object/items", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ListResponse[Item]
	if err := decodeJSON(resp.Body, &result, "items response"); err != nil {
		return nil, err
	}

	return result.Data.Data, nil
}

// ListItems returns all items in the vault.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) ListItems(ctx context.Context) ([]Item, error) {
	var items []Item
	err := c.withAutoUnlock(ctx, func() error {
		var err error
		items, err = c.listItemsInternal(ctx)
		return err
	})
	return items, err
}

// searchItemsInternal performs the actual SearchItems API call
func (c *Client) searchItemsInternal(ctx context.Context, searchURL string) ([]Item, error) {
	params := url.Values{}
	params.Set("url", searchURL)

	resp, err := c.doRequest(ctx, "GET", "/list/object/items?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ListResponse[Item]
	if err := decodeJSON(resp.Body, &result, "search response"); err != nil {
		return nil, err
	}

	return result.Data.Data, nil
}

// SearchItems searches for items matching the given URL.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) SearchItems(ctx context.Context, searchURL string) ([]Item, error) {
	var items []Item
	err := c.withAutoUnlock(ctx, func() error {
		var err error
		items, err = c.searchItemsInternal(ctx, searchURL)
		return err
	})
	return items, err
}

// getItemInternal performs the actual GetItem API call
func (c *Client) getItemInternal(ctx context.Context, id string) (*Item, error) {
	resp, err := c.doRequest(ctx, "GET", "/object/item/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result APIResponse[Item]
	if err := decodeJSON(resp.Body, &result, "item response"); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// GetItem returns a specific item by ID.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) GetItem(ctx context.Context, id string) (*Item, error) {
	var item *Item
	err := c.withAutoUnlock(ctx, func() error {
		var err error
		item, err = c.getItemInternal(ctx, id)
		return err
	})
	return item, err
}

// createItemInternal performs the actual CreateItem API call
func (c *Client) createItemInternal(ctx context.Context, item CreateItemRequest) (*Item, error) {
	body, err := jsonBody(item)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(ctx, "POST", "/object/item", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result APIResponse[Item]
	if err := decodeJSON(resp.Body, &result, "create item response"); err != nil {
		return nil, err
	}

	if result.Data.ID == "" {
		return nil, fmt.Errorf("created item has no ID")
	}

	return &result.Data, nil
}

// CreateItem creates a new item in the vault.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) CreateItem(ctx context.Context, item CreateItemRequest) (*Item, error) {
	var result *Item
	err := c.withAutoUnlock(ctx, func() error {
		var err error
		result, err = c.createItemInternal(ctx, item)
		return err
	})
	return result, err
}

// updateItemInternal performs the actual UpdateItem API call
func (c *Client) updateItemInternal(ctx context.Context, id string, item CreateItemRequest) (*Item, error) {
	body, err := jsonBody(item)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(ctx, "PUT", "/object/item/"+id, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result APIResponse[Item]
	if err := decodeJSON(resp.Body, &result, "update response"); err != nil {
		return nil, err
	}

	return &result.Data, nil
}

// UpdateItem updates an existing item.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) UpdateItem(ctx context.Context, id string, item CreateItemRequest) (*Item, error) {
	var result *Item
	err := c.withAutoUnlock(ctx, func() error {
		var err error
		result, err = c.updateItemInternal(ctx, id, item)
		return err
	})
	return result, err
}

// deleteItemInternal performs the actual DeleteItem API call
func (c *Client) deleteItemInternal(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/object/item/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// DeleteItem deletes an item by ID.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) DeleteItem(ctx context.Context, id string) error {
	return c.withAutoUnlock(ctx, func() error {
		return c.deleteItemInternal(ctx, id)
	})
}

// listFoldersInternal performs the actual API call without auto-unlock logic.
func (c *Client) listFoldersInternal(ctx context.Context) ([]Folder, error) {
	resp, err := c.doRequest(ctx, "GET", "/list/object/folders", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ListResponse[Folder]
	if err := decodeJSON(resp.Body, &result, "folders response"); err != nil {
		return nil, err
	}

	return result.Data.Data, nil
}

// ListFolders returns all folders in the vault.
// Automatically prompts for unlock if the vault is locked.
func (c *Client) ListFolders(ctx context.Context) ([]Folder, error) {
	var folders []Folder
	err := c.withAutoUnlock(ctx, func() error {
		var err error
		folders, err = c.listFoldersInternal(ctx)
		return err
	})
	return folders, err
}

// doRequest performs an HTTP request to the Bitwarden API
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		// Read at most 4096 bytes of the response body
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		bodyStr := string(bodyBytes)

		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Path:       path,
			debugBody:  bodyStr,
		}

		if c.debug.Load() {
			fmt.Fprintf(os.Stderr, "HTTP error %d on %s: %s\n", resp.StatusCode, path, logHTTPBodySnippet("Response", bodyStr))
		}

		return nil, apiErr
	}

	return resp, nil
}

// SessionManager returns the session manager for this client
func (c *Client) SessionManager() *SessionManager {
	return c.session
}

// EnsureUnlocked ensures the vault is unlocked.
// If auto-unlock is disabled and the vault is locked, returns ErrVaultLocked.
func (c *Client) EnsureUnlocked(ctx context.Context) error {
	return c.ensureUnlocked(ctx)
}
