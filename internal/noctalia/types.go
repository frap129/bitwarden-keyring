// Package noctalia provides an IPC client for the Noctalia Quickshell plugin
// to enable Noctalia UI integration for password prompts.
package noctalia

import "errors"

// KeyringRequest is sent to the Noctalia Quickshell plugin to request a password prompt.
// The plugin will display a UI dialog and return the password via KeyringResponse.
type KeyringRequest struct {
	Type        string `json:"type"`         // Always "keyring_request"
	Cookie      string `json:"cookie"`       // Unique request ID (hex-encoded random bytes)
	Title       string `json:"title"`        // Dialog title (e.g., "Bitwarden Keyring")
	Message     string `json:"message"`      // Prompt message (e.g., "Enter Master Password")
	Description string `json:"description"`  // Optional description
	PasswordNew bool   `json:"password_new"` // Whether this is for a new password
	ConfirmOnly bool   `json:"confirm_only"` // Whether to just confirm (no password input)
}

// KeyringResponse is received from the Noctalia Quickshell plugin after the user
// interacts with the password dialog.
type KeyringResponse struct {
	Type     string `json:"type"`               // Always "keyring_response"
	ID       string `json:"id"`                 // Matches the request cookie
	Result   string `json:"result"`             // "ok", "cancelled", or "confirmed"
	Password string `json:"password,omitempty"` // Password if result is "ok"
}

// Result constants for KeyringResponse.Result
const (
	ResultOK        = "ok"        // Password provided successfully
	ResultCancelled = "cancelled" // User cancelled the prompt
	ResultConfirmed = "confirmed" // User confirmed (for confirm_only requests)
)

// Error types for Noctalia IPC operations
var (
	// ErrSocketNotFound indicates the Noctalia agent socket does not exist
	ErrSocketNotFound = errors.New("noctalia socket not found")

	// ErrConnectionFailed indicates a failure to connect to the Noctalia plugin
	ErrConnectionFailed = errors.New("failed to connect to noctalia plugin")

	// ErrTimeout indicates the password request timed out
	ErrTimeout = errors.New("noctalia request timed out")

	// ErrCancelled indicates the user cancelled the password prompt
	ErrCancelled = errors.New("user cancelled password prompt")

	// ErrConfirmOnly indicates the request was a confirm-only request that was acknowledged
	ErrConfirmOnly = errors.New("confirm-only request acknowledged")

	// ErrProtocolError indicates an unexpected response from the agent
	ErrProtocolError = errors.New("noctalia protocol error")

	// ErrCookieMismatch indicates the response cookie doesn't match the request
	ErrCookieMismatch = errors.New("response cookie does not match request")
)
