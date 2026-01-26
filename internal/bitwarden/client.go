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
	"sync"
	"time"
)

// Client provides access to the Bitwarden CLI REST API
type Client struct {
	baseURL    string
	httpClient *http.Client
	session    *SessionManager
	mu         sync.RWMutex
	serveCmd   *exec.Cmd
}

// NewClient creates a new Bitwarden API client
func NewClient(port int) *Client {
	return NewClientWithConfig(port, DefaultSessionConfig())
}

// NewClientWithConfig creates a new Bitwarden API client with custom session config
func NewClientWithConfig(port int, sessionCfg SessionConfig) *Client {
	return &Client{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		session: NewSessionManagerWithConfig(sessionCfg),
	}
}

// StartServe starts the 'bw serve' process if not already running
func (c *Client) StartServe(ctx context.Context, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already running
	if c.serveCmd != nil && c.serveCmd.Process != nil {
		return nil
	}

	// Check if bw is available
	if _, err := exec.LookPath("bw"); err != nil {
		return fmt.Errorf("bitwarden CLI (bw) not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, "bw", "serve", "--hostname", "127.0.0.1", "--port", fmt.Sprintf("%d", port))

	// Pass through session key if available
	sessionKey := c.session.GetSession()
	if sessionKey != "" {
		cmd.Env = append(os.Environ(), "BW_SESSION="+sessionKey)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start bw serve: %w", err)
	}

	c.serveCmd = cmd

	// Wait for server to be ready
	return c.waitForReady(ctx)
}

// waitForReady waits for the bw serve API to be responsive
func (c *Client) waitForReady(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for bw serve to start")
		case <-ticker.C:
			_, err := c.Status(ctx)
			if err == nil {
				return nil
			}
		}
	}
}

// Stop stops the bw serve process
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.serveCmd != nil && c.serveCmd.Process != nil {
		if err := c.serveCmd.Process.Kill(); err != nil {
			return err
		}
		c.serveCmd = nil
	}
	return nil
}

// Status returns the current vault status
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	resp, err := c.doRequest(ctx, "GET", "/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode status response: %w", err)
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

// Unlock unlocks the vault with the provided password
func (c *Client) Unlock(ctx context.Context, password string) (string, error) {
	payload := UnlockRequest{Password: password}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	resp, err := c.doRequest(ctx, "POST", "/unlock", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result UnlockResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode unlock response: %w", err)
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

// Sync synchronizes the vault with the server
func (c *Client) Sync(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "POST", "/sync", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ListItems returns all items in the vault
func (c *Client) ListItems(ctx context.Context) ([]Item, error) {
	resp, err := c.doRequest(ctx, "GET", "/list/object/items", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ListResponse[Item]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode items response: %w", err)
	}

	return result.Data.Data, nil
}

// SearchItems searches for items matching the given URL
func (c *Client) SearchItems(ctx context.Context, searchURL string) ([]Item, error) {
	params := url.Values{}
	params.Set("url", searchURL)

	resp, err := c.doRequest(ctx, "GET", "/list/object/items?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ListResponse[Item]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	return result.Data.Data, nil
}

// GetItem returns a specific item by ID
func (c *Client) GetItem(ctx context.Context, id string) (*Item, error) {
	resp, err := c.doRequest(ctx, "GET", "/object/item/"+id, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result APIResponse[Item]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode item response: %w", err)
	}

	return &result.Data, nil
}

// CreateItem creates a new item in the vault
func (c *Client) CreateItem(ctx context.Context, item CreateItemRequest) (*Item, error) {
	body, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(ctx, "POST", "/object/item", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read raw response for debugging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result APIResponse[Item]
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode create response: %w (body: %s)", err, string(respBody))
	}

	if result.Data.ID == "" {
		return nil, fmt.Errorf("created item has no ID (body: %s)", string(respBody))
	}

	return &result.Data, nil
}

// UpdateItem updates an existing item
func (c *Client) UpdateItem(ctx context.Context, id string, item CreateItemRequest) (*Item, error) {
	body, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}

	resp, err := c.doRequest(ctx, "PUT", "/object/item/"+id, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result APIResponse[Item]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode update response: %w", err)
	}

	return &result.Data, nil
}

// DeleteItem deletes an item by ID
func (c *Client) DeleteItem(ctx context.Context, id string) error {
	resp, err := c.doRequest(ctx, "DELETE", "/object/item/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ListFolders returns all folders in the vault
func (c *Client) ListFolders(ctx context.Context) ([]Folder, error) {
	resp, err := c.doRequest(ctx, "GET", "/list/object/folders", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ListResponse[Folder]
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode folders response: %w", err)
	}

	return result.Data.Data, nil
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
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return resp, nil
}

// SessionManager returns the session manager for this client
func (c *Client) SessionManager() *SessionManager {
	return c.session
}
