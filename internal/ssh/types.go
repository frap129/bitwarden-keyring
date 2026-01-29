// Package ssh implements an SSH agent that uses Bitwarden as the backend key storage.
package ssh

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

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
	Signer ssh.Signer
}

// Common errors for the SSH agent.
var (
	ErrKeyNotFound   = errors.New("ssh key not found")
	ErrVaultLocked   = errors.New("bitwarden vault is locked")
	ErrReadOnly      = errors.New("ssh agent is read-only")
	ErrInvalidKey    = errors.New("invalid ssh key format")
	ErrSocketExists  = errors.New("socket already exists")
	ErrNotSSHKeyItem = errors.New("item is not an SSH key")
)
