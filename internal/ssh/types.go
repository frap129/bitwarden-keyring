// Package ssh implements an SSH agent that uses Bitwarden as the backend key storage.
package ssh

import (
	"errors"
	"os"
	"path/filepath"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// DefaultSocketPath returns the default path for the SSH agent socket.
// It uses $XDG_RUNTIME_DIR/bitwarden-keyring/ssh.sock if XDG_RUNTIME_DIR is set,
// otherwise falls back to /tmp/bitwarden-keyring-ssh.sock.
func DefaultSocketPath() string {
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		return filepath.Join(xdgRuntime, "bitwarden-keyring", "ssh.sock")
	}
	return "/tmp/bitwarden-keyring-ssh.sock"
}

// SSHKeyItem wraps a Bitwarden item with its parsed SSH key signer.
type SSHKeyItem struct {
	Item   *bitwarden.Item
	Signer cryptossh.Signer
}

// ParseError represents a key that failed to parse.
type ParseError struct {
	ItemName string // Name of the Bitwarden item that failed to parse
	Err      error  // The parse error
}

// Error implements the error interface.
func (e ParseError) Error() string {
	return e.ItemName + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e ParseError) Unwrap() error {
	return e.Err
}

// ListSSHKeysResult contains successfully parsed keys and any parse errors.
type ListSSHKeysResult struct {
	Keys   []*SSHKeyItem // Successfully parsed SSH keys
	Errors []ParseError  // Keys that failed to parse
}

// Common errors for the SSH agent.
var (
	ErrKeyNotFound    = errors.New("ssh key not found")
	ErrVaultLocked    = errors.New("bitwarden vault is locked")
	ErrReadOnly       = errors.New("ssh agent is read-only")
	ErrInvalidKey     = errors.New("invalid ssh key format")
	ErrSocketExists   = errors.New("socket already exists")
	ErrNotSocket      = errors.New("path exists but is not a socket")
	ErrNotSSHKeyItem  = errors.New("item is not an SSH key")
	ErrAlreadyStarted = errors.New("server already started")
)
