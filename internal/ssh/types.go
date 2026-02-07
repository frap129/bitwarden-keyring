// Package ssh implements an SSH agent that uses Bitwarden as the backend key storage.
package ssh

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// BitwardenClient defines the interface for Bitwarden operations needed by the SSH agent.
// This interface allows for easier testing by providing a way to mock the client.
// The client handles vault unlocking transparently - components don't need to check lock state.
type BitwardenClient interface {
	ListItems(ctx context.Context) ([]bitwarden.Item, error)
	CreateItem(ctx context.Context, req bitwarden.CreateItemRequest) (*bitwarden.Item, error)
	DeleteItem(ctx context.Context, id string) error
	Lock(ctx context.Context) error
	Unlock(ctx context.Context, password string) (string, error)
}

// DefaultSocketPath returns the default path for the SSH agent socket.
// It uses $XDG_RUNTIME_DIR/bitwarden-keyring/ssh.sock if XDG_RUNTIME_DIR is set,
// otherwise falls back to /tmp/bitwarden-keyring-<uid>/ssh.sock.
func DefaultSocketPath() string {
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		return filepath.Join(xdgRuntime, "bitwarden-keyring", "ssh.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("bitwarden-keyring-%d", os.Geteuid()), "ssh.sock")
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
	ErrKeyNotFound = errors.New("ssh key not found")
	ErrVaultLocked = errors.New("bitwarden vault is locked")
	ErrReadOnly    = errors.New("ssh agent is read-only")

	// ErrRemoveAllNotSupported is returned by RemoveAll to prevent bulk deletion
	// of SSH keys. This is a deliberate safety measure because SSH keys stored
	// in Bitwarden should not be mass-deleted through the agent interface.
	// Callers should delete keys individually via Remove() instead.
	ErrRemoveAllNotSupported = errors.New("ssh-add -D (remove all) is not supported")

	ErrInvalidKey        = errors.New("invalid ssh key format")
	ErrSocketExists      = errors.New("socket already exists")
	ErrNotSocket         = errors.New("path exists but is not a socket")
	ErrNotSSHKeyItem     = errors.New("item is not an SSH key")
	ErrAlreadyStarted    = errors.New("server already started")
	ErrInsecureSocketDir = errors.New("socket directory is insecure: must not be a symlink, must be owned by current user, and must not be world-accessible")
)

// ItemLister is a minimal interface for listing items from a Bitwarden-like source.
// This is satisfied by BitwardenClient and allows ListSSHKeys to accept any client
// that can list items, enabling easier testing and composition.
type ItemLister interface {
	ListItems(ctx context.Context) ([]bitwarden.Item, error)
}
