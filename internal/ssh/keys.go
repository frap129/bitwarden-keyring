package ssh

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// IsSSHKeyItem returns true if the given Bitwarden item is an SSH key.
func IsSSHKeyItem(item *bitwarden.Item) bool {
	return item != nil && item.Type == bitwarden.ItemTypeSSHKey && item.SSHKey != nil
}

// ParseSSHKey parses the private key from a Bitwarden SSH key item and returns a Signer.
func ParseSSHKey(item *bitwarden.Item) (ssh.Signer, error) {
	if !IsSSHKeyItem(item) {
		return nil, ErrNotSSHKeyItem
	}

	if item.SSHKey.PrivateKey == "" {
		return nil, fmt.Errorf("%w: empty private key", ErrInvalidKey)
	}

	signer, err := ssh.ParsePrivateKey([]byte(item.SSHKey.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	return signer, nil
}

// ParseSSHKeyWithPassphrase parses an encrypted private key using the provided passphrase.
func ParseSSHKeyWithPassphrase(item *bitwarden.Item, passphrase []byte) (ssh.Signer, error) {
	if !IsSSHKeyItem(item) {
		return nil, ErrNotSSHKeyItem
	}

	if item.SSHKey.PrivateKey == "" {
		return nil, fmt.Errorf("%w: empty private key", ErrInvalidKey)
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(item.SSHKey.PrivateKey), passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	return signer, nil
}

// KeyLister defines the interface for listing items from Bitwarden.
type KeyLister interface {
	ListItems(ctx context.Context) ([]bitwarden.Item, error)
}

// ListSSHKeys retrieves all SSH key items from the Bitwarden vault
// and returns them with their parsed signers.
func ListSSHKeys(ctx context.Context, client KeyLister) ([]*SSHKeyItem, error) {
	items, err := client.ListItems(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list items: %w", err)
	}

	var sshKeys []*SSHKeyItem
	for i := range items {
		item := &items[i]
		if !IsSSHKeyItem(item) {
			continue
		}

		signer, err := ParseSSHKey(item)
		if err != nil {
			// Skip keys that fail to parse but log them
			// In production, we might want to handle this differently
			continue
		}

		sshKeys = append(sshKeys, &SSHKeyItem{
			Item:   item,
			Signer: signer,
		})
	}

	return sshKeys, nil
}

// FindSSHKeyByPublicKey searches for an SSH key item that matches the given public key.
func FindSSHKeyByPublicKey(keys []*SSHKeyItem, pubKey ssh.PublicKey) (*SSHKeyItem, bool) {
	targetBlob := pubKey.Marshal()
	for _, key := range keys {
		if key.Signer != nil {
			keyBlob := key.Signer.PublicKey().Marshal()
			if string(keyBlob) == string(targetBlob) {
				return key, true
			}
		}
	}
	return nil, false
}
