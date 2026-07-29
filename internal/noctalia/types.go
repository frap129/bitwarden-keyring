// Package noctalia provides a Noctalia v5 client for password prompts.
package noctalia

import "errors"

// KeyringRequest is sent to the Noctalia v5 plugin to request a password prompt.
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

// KeyringResponse is received from the Noctalia v5 plugin after the user
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

// Message type constants
const (
	MessageTypeRequest  = "keyring_request"
	MessageTypeResponse = "keyring_response"
	MessageTypeResult   = "keyring_result"
)

// KeyringResult is sent from the Go client back to the Noctalia v5 plugin after an unlock attempt.
// This enables two-phase communication for password retry support.
type KeyringResult struct {
	Type    string `json:"type"`            // Always "keyring_result"
	ID      string `json:"id"`              // Matches the request cookie
	Success bool   `json:"success"`         // Whether unlock succeeded
	Error   string `json:"error,omitempty"` // Error message if !Success
	Retry   bool   `json:"retry,omitempty"` // Whether retry is allowed (only when !Success)
}

// Error types for Noctalia v5 operations.
var (
	ErrPluginUnavailable = errors.New("noctalia v5 plugin unavailable")
	ErrSocketNotFound    = ErrPluginUnavailable
	ErrConnectionFailed  = ErrPluginUnavailable

	ErrTimeout = errors.New("noctalia request timed out")

	ErrCancelled = errors.New("user cancelled password prompt")

	ErrConfirmOnly = errors.New("confirm-only request acknowledged")

	ErrProtocolError = errors.New("noctalia protocol error")

	ErrCookieMismatch = errors.New("response cookie does not match request")

	ErrSessionClosed = errors.New("noctalia session closed")
)
