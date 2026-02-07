package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/logging"
)

// Keyring implements the agent.Agent interface using Bitwarden as the key store.
type Keyring struct {
	client BitwardenClient
	mu     sync.RWMutex
	keys   []*SSHKeyItem // cached keys
	debug  bool          // enable debug logging
}

// NewKeyring creates a new Keyring backed by the given Bitwarden client.
func NewKeyring(client BitwardenClient) *Keyring {
	return &Keyring{
		client: client,
	}
}

// SetDebug enables or disables debug logging.
func (k *Keyring) SetDebug(debug bool) {
	k.debug = debug
}

// refreshKeys reloads the SSH keys from Bitwarden.
func (k *Keyring) refreshKeys(ctx context.Context) error {
	result, err := ListSSHKeys(ctx, k.client)
	if err != nil {
		return err
	}

	// Log parse errors in debug mode
	if k.debug && len(result.Errors) > 0 {
		for _, parseErr := range result.Errors {
			logging.L.With("component", "ssh-agent").Warn("failed to parse key", "item", parseErr.ItemName, "error", parseErr.Err)
		}
	}

	k.mu.Lock()
	k.keys = result.Keys
	k.mu.Unlock()

	return nil
}

// List returns the identities known to the agent.
func (k *Keyring) List() ([]*agent.Key, error) {
	ctx := context.Background()

	// Refresh keys from Bitwarden (client handles auto-unlock)
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
func (k *Keyring) Sign(key cryptossh.PublicKey, data []byte) (*cryptossh.Signature, error) {
	return k.SignWithFlags(key, data, 0)
}

// SignWithFlags signs data with the specified flags.
func (k *Keyring) SignWithFlags(key cryptossh.PublicKey, data []byte, flags agent.SignatureFlags) (*cryptossh.Signature, error) {
	ctx := context.Background()

	// Refresh keys if cache is empty (client handles auto-unlock)
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

	// If not found, try refreshing once and retry
	if !found {
		if err := k.refreshKeys(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh keys: %w", err)
		}
		k.mu.RLock()
		sshKey, found = FindSSHKeyByPublicKey(k.keys, key)
		k.mu.RUnlock()
		if !found {
			return nil, ErrKeyNotFound
		}
	}

	// Handle signature algorithm based on flags
	var algo string
	switch {
	case flags&agent.SignatureFlagRsaSha256 != 0:
		algo = cryptossh.KeyAlgoRSASHA256
	case flags&agent.SignatureFlagRsaSha512 != 0:
		algo = cryptossh.KeyAlgoRSASHA512
	default:
		algo = ""
	}

	// Use AlgorithmSigner if available and algorithm is specified
	if algo != "" {
		if algSigner, ok := sshKey.Signer.(cryptossh.AlgorithmSigner); ok {
			return algSigner.SignWithAlgorithm(rand.Reader, data, algo)
		}
	}

	return sshKey.Signer.Sign(rand.Reader, data)
}

// Add adds a key to the agent by creating an SSH key item in Bitwarden.
// Note: The LifetimeSecs and ConfirmBeforeUse fields are ignored as Bitwarden
// does not support these options.
func (k *Keyring) Add(key agent.AddedKey) error {
	if key.PrivateKey == nil {
		return fmt.Errorf("private key is required")
	}

	ctx := context.Background()

	// Create a signer from the private key to get the public key
	signer, err := cryptossh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer from key: %w", err)
	}

	// Check for duplicate by fingerprint
	fingerprint := cryptossh.FingerprintSHA256(signer.PublicKey())

	// Refresh keys and check for existing key with same fingerprint (client handles auto-unlock)
	if err := k.refreshKeys(ctx); err != nil {
		return fmt.Errorf("failed to refresh keys: %w", err)
	}

	k.mu.RLock()
	_, found := FindSSHKeyByPublicKey(k.keys, signer.PublicKey())
	k.mu.RUnlock()

	if found {
		// Key already exists, return success (idempotent)
		if k.debug {
			logging.L.With("component", "ssh-agent").Info("key already exists, skipping", "fingerprint", fingerprint)
		}
		return nil
	}

	// Marshal the private key to OpenSSH format
	privateKeyPEM, err := marshalPrivateKeyOpenSSH(key.PrivateKey, key.Comment)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Format the public key
	publicKeyStr := formatAuthorizedKey(signer.PublicKey(), key.Comment)

	// Determine the item name
	name := key.Comment
	if name == "" {
		name = fingerprint
	}

	// Create the Bitwarden item (client handles auto-unlock)
	req := bitwarden.CreateItemRequest{
		Type: bitwarden.ItemTypeSSHKey,
		Name: name,
		SSHKey: &bitwarden.SSHKey{
			PrivateKey:     string(privateKeyPEM),
			PublicKey:      publicKeyStr,
			KeyFingerprint: fingerprint,
		},
	}

	createdItem, err := k.client.CreateItem(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create SSH key item: %w", err)
	}

	// Add to cache
	k.mu.Lock()
	k.keys = append(k.keys, &SSHKeyItem{
		Item:   createdItem,
		Signer: signer,
	})
	k.mu.Unlock()

	if k.debug {
		logging.L.With("component", "ssh-agent").Info("added key", "fingerprint", fingerprint, "item_id", createdItem.ID)
	}

	return nil
}

// Remove removes a key from the agent by deleting the SSH key item from Bitwarden.
func (k *Keyring) Remove(key cryptossh.PublicKey) error {
	if key == nil {
		return fmt.Errorf("public key is required")
	}

	ctx := context.Background()

	// Refresh keys from Bitwarden (client handles auto-unlock)
	if err := k.refreshKeys(ctx); err != nil {
		return fmt.Errorf("failed to refresh keys: %w", err)
	}

	// Find the key in cache
	k.mu.RLock()
	sshKey, found := FindSSHKeyByPublicKey(k.keys, key)
	k.mu.RUnlock()

	if !found {
		return ErrKeyNotFound
	}

	// Delete from Bitwarden
	if err := k.client.DeleteItem(ctx, sshKey.Item.ID); err != nil {
		return fmt.Errorf("failed to delete SSH key item: %w", err)
	}

	// Remove from cache
	k.mu.Lock()
	targetBlob := key.Marshal()
	newKeys := make([]*SSHKeyItem, 0, len(k.keys)-1)
	for _, cachedKey := range k.keys {
		if cachedKey.Signer != nil {
			keyBlob := cachedKey.Signer.PublicKey().Marshal()
			if !bytes.Equal(keyBlob, targetBlob) {
				newKeys = append(newKeys, cachedKey)
			}
		}
	}
	k.keys = newKeys
	k.mu.Unlock()

	if k.debug {
		logging.L.With("component", "ssh-agent").Info("removed key", "fingerprint", cryptossh.FingerprintSHA256(key), "item_id", sshKey.Item.ID)
	}

	return nil
}

// RemoveAll is intentionally not supported as a safety guard against bulk key deletion.
//
// This method is required by the agent.ExtendedAgent interface, but returning an error
// prevents accidental mass deletion of SSH keys from Bitwarden. SSH keys stored in
// Bitwarden should be deleted individually through explicit user action, not through
// the ssh-add -D command which could wipe all keys without confirmation.
//
// Callers should remove keys individually via Remove(key).
func (k *Keyring) RemoveAll() error {
	return ErrRemoveAllNotSupported
}

// Lock locks the Bitwarden vault, clearing the key cache.
//
// Note: The passphrase parameter is ignored. This agent implements vault-level
// locking rather than passphrase-based agent locking as used by ssh-agent.
// When the Bitwarden vault is locked, the agent cannot access any keys.
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

// Unlock unlocks the Bitwarden vault and refreshes the key cache.
//
// Note: The passphrase parameter is ignored. This agent uses Bitwarden's
// authentication mechanism instead. The client will automatically prompt
// for the master password if the vault is locked (via SessionManager).
// This differs from ssh-agent's passphrase-based locking.
func (k *Keyring) Unlock(passphrase []byte) error {
	ctx := context.Background()
	// Just refresh keys - the client handles auto-unlock transparently
	return k.refreshKeys(ctx)
}

// Signers returns signers for all available keys.
func (k *Keyring) Signers() ([]cryptossh.Signer, error) {
	ctx := context.Background()

	// Refresh keys from Bitwarden (client handles auto-unlock)
	if err := k.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %w", err)
	}

	k.mu.RLock()
	defer k.mu.RUnlock()

	var signers []cryptossh.Signer
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
