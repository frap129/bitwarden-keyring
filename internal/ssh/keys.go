package ssh

import (
	"bytes"
	"context"
	"crypto"
	"encoding/pem"
	"fmt"
	"strings"

	cryptossh "golang.org/x/crypto/ssh"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// IsSSHKeyItem returns true if the given Bitwarden item is an SSH key.
func IsSSHKeyItem(item *bitwarden.Item) bool {
	return item != nil && item.Type == bitwarden.ItemTypeSSHKey && item.SSHKey != nil
}

// ParseSSHKey parses the private key from a Bitwarden SSH key item and returns a Signer.
func ParseSSHKey(item *bitwarden.Item) (cryptossh.Signer, error) {
	if !IsSSHKeyItem(item) {
		return nil, ErrNotSSHKeyItem
	}

	if item.SSHKey.PrivateKey == "" {
		return nil, fmt.Errorf("%w: empty private key", ErrInvalidKey)
	}

	signer, err := cryptossh.ParsePrivateKey([]byte(item.SSHKey.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	return signer, nil
}

// ParseSSHKeyWithPassphrase parses an encrypted private key using the provided passphrase.
func ParseSSHKeyWithPassphrase(item *bitwarden.Item, passphrase []byte) (cryptossh.Signer, error) {
	if !IsSSHKeyItem(item) {
		return nil, ErrNotSSHKeyItem
	}

	if item.SSHKey.PrivateKey == "" {
		return nil, fmt.Errorf("%w: empty private key", ErrInvalidKey)
	}

	signer, err := cryptossh.ParsePrivateKeyWithPassphrase([]byte(item.SSHKey.PrivateKey), passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}

	return signer, nil
}

// ListSSHKeys retrieves all SSH key items from the Bitwarden vault
// and returns them with their parsed signers. Parse errors are collected
// in the result struct so callers can decide how to handle them.
// The client parameter accepts any type satisfying ItemLister (including BitwardenClient).
func ListSSHKeys(ctx context.Context, client ItemLister) (*ListSSHKeysResult, error) {
	items, err := client.ListItems(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list items: %w", err)
	}

	result := &ListSSHKeysResult{}
	for i := range items {
		item := &items[i]
		if !IsSSHKeyItem(item) {
			continue
		}

		signer, err := ParseSSHKey(item)
		if err != nil {
			result.Errors = append(result.Errors, ParseError{
				ItemName: item.Name,
				Err:      err,
			})
			continue
		}

		result.Keys = append(result.Keys, &SSHKeyItem{
			Item:   item,
			Signer: signer,
		})
	}

	return result, nil
}

// FindSSHKeyByPublicKey searches for an SSH key item that matches the given public key.
func FindSSHKeyByPublicKey(keys []*SSHKeyItem, pubKey cryptossh.PublicKey) (*SSHKeyItem, bool) {
	targetBlob := pubKey.Marshal()
	for _, key := range keys {
		if key.Signer != nil {
			keyBlob := key.Signer.PublicKey().Marshal()
			if bytes.Equal(keyBlob, targetBlob) {
				return key, true
			}
		}
	}
	return nil, false
}

// marshalPrivateKeyOpenSSH converts a crypto.PrivateKey to OpenSSH PEM format.
// The comment is embedded in the key file.
func marshalPrivateKeyOpenSSH(key crypto.PrivateKey, comment string) ([]byte, error) {
	pemBlock, err := cryptossh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// formatAuthorizedKey returns the public key in authorized_keys format with optional comment.
func formatAuthorizedKey(pub cryptossh.PublicKey, comment string) string {
	authKey := strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		return authKey + " " + comment
	}
	return authKey
}
