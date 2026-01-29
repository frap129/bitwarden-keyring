package ssh

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// Keyring implements the agent.Agent interface using Bitwarden as the key store.
// It is read-only - keys cannot be added or removed via the SSH agent protocol.
type Keyring struct {
	client *bitwarden.Client
	mu     sync.RWMutex
	keys   []*SSHKeyItem // cached keys
}

// NewKeyring creates a new Keyring backed by the given Bitwarden client.
func NewKeyring(client *bitwarden.Client) *Keyring {
	return &Keyring{
		client: client,
	}
}

// refreshKeys reloads the SSH keys from Bitwarden.
func (k *Keyring) refreshKeys(ctx context.Context) error {
	keys, err := ListSSHKeys(ctx, k.client)
	if err != nil {
		return err
	}

	k.mu.Lock()
	k.keys = keys
	k.mu.Unlock()

	return nil
}

// List returns the identities known to the agent.
func (k *Keyring) List() ([]*agent.Key, error) {
	ctx := context.Background()

	// Check if vault is locked
	locked, err := k.client.IsLocked(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check vault status: %w", err)
	}
	if locked {
		return nil, ErrVaultLocked
	}

	// Refresh keys from Bitwarden
	if err := k.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	var agentKeys []*agent.Key
	for _, key := range k.keys {
		if key.Signer == nil {
			continue
		}
		pubKey := key.Signer.PublicKey()
		agentKeys = append(agentKeys, &agent.Key{
			Format:  pubKey.Type(),
			Blob:    pubKey.Marshal(),
			Comment: key.Item.Name,
		})
	}

	return agentKeys, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (k *Keyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return k.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with the specified flags.
func (k *Keyring) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	ctx := context.Background()

	// Check if vault is locked
	locked, err := k.client.IsLocked(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check vault status: %w", err)
	}
	if locked {
		return nil, ErrVaultLocked
	}

	// Refresh keys if cache is empty
	k.mu.RLock()
	needsRefresh := len(k.keys) == 0
	k.mu.RUnlock()

	if needsRefresh {
		if err := k.refreshKeys(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh keys: %w", err)
		}
	}

	k.mu.RLock()
	sshKey, found := FindSSHKeyByPublicKey(k.keys, key)
	k.mu.RUnlock()

	if !found {
		return nil, ErrKeyNotFound
	}

	// Handle signature algorithm based on flags
	var algo string
	switch {
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algo = ssh.KeyAlgoRSASHA256
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algo = ssh.KeyAlgoRSASHA512
	default:
		algo = ""
	}

	// Use AlgorithmSigner if available and algorithm is specified
	if algo != "" {
		if algSigner, ok := sshKey.Signer.(ssh.AlgorithmSigner); ok {
			return algSigner.SignWithAlgorithm(rand.Reader, data, algo)
		}
	}

	return sshKey.Signer.Sign(rand.Reader, data)
}

// Add is not supported - this is a read-only agent.
func (k *Keyring) Add(key agent.AddedKey) error {
	return ErrReadOnly
}

// Remove is not supported - this is a read-only agent.
func (k *Keyring) Remove(key ssh.PublicKey) error {
	return ErrReadOnly
}

// RemoveAll is not supported - this is a read-only agent.
func (k *Keyring) RemoveAll() error {
	return ErrReadOnly
}

// Lock locks the Bitwarden vault.
func (k *Keyring) Lock(passphrase []byte) error {
	ctx := context.Background()
	if err := k.client.Lock(ctx); err != nil {
		return fmt.Errorf("failed to lock vault: %w", err)
	}

	k.mu.Lock()
	k.keys = nil
	k.mu.Unlock()

	return nil
}

// Unlock unlocks the Bitwarden vault.
// Note: The passphrase parameter is ignored; Bitwarden uses its own unlock mechanism
// via the SessionManager which prompts for the master password.
func (k *Keyring) Unlock(passphrase []byte) error {
	ctx := context.Background()

	// Use the SessionManager's PromptForPassword to get the master password
	// and then unlock the vault
	password, err := k.client.SessionManager().PromptForPassword()
	if err != nil {
		return fmt.Errorf("failed to get password: %w", err)
	}

	if _, err := k.client.Unlock(ctx, password); err != nil {
		return fmt.Errorf("failed to unlock vault: %w", err)
	}

	// Refresh keys after unlock
	return k.refreshKeys(ctx)
}

// Signers returns signers for all available keys.
func (k *Keyring) Signers() ([]ssh.Signer, error) {
	ctx := context.Background()

	// Check if vault is locked
	locked, err := k.client.IsLocked(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check vault status: %w", err)
	}
	if locked {
		return nil, ErrVaultLocked
	}

	// Refresh keys from Bitwarden
	if err := k.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	var signers []ssh.Signer
	for _, key := range k.keys {
		if key.Signer != nil {
			signers = append(signers, key.Signer)
		}
	}

	return signers, nil
}

// Extension processes agent extensions.
// Currently no extensions are supported.
func (k *Keyring) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// Verify that Keyring implements agent.ExtendedAgent.
var _ agent.ExtendedAgent = (*Keyring)(nil)
