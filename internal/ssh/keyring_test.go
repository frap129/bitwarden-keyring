package ssh

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// mockBitwardenClient implements KeyLister for testing
type mockBitwardenClient struct {
	items    []bitwarden.Item
	locked   bool
	unlocked bool
}

func (m *mockBitwardenClient) ListItems(ctx context.Context) ([]bitwarden.Item, error) {
	if m.locked {
		return nil, ErrVaultLocked
	}
	return m.items, nil
}

func (m *mockBitwardenClient) IsLocked(ctx context.Context) (bool, error) {
	return m.locked, nil
}

func (m *mockBitwardenClient) Lock(ctx context.Context) error {
	m.locked = true
	m.unlocked = false
	return nil
}

func (m *mockBitwardenClient) Unlock(ctx context.Context, password string) (string, error) {
	m.locked = false
	m.unlocked = true
	return "session", nil
}

func (m *mockBitwardenClient) SessionManager() *bitwarden.SessionManager {
	return nil
}

// testableKeyring wraps Keyring for testing with a mock client
type testableKeyring struct {
	*Keyring
	mock *mockBitwardenClient
}

func newTestableKeyring(items []bitwarden.Item, locked bool) *testableKeyring {
	mock := &mockBitwardenClient{
		items:  items,
		locked: locked,
	}

	// We can't use NewKeyring directly since it needs a real client
	// Instead, create a Keyring with nil client and override the refresh method
	kr := &Keyring{}

	return &testableKeyring{
		Keyring: kr,
		mock:    mock,
	}
}

// Override refreshKeys for testing
func (tk *testableKeyring) refreshKeysFromMock(ctx context.Context) error {
	if tk.mock.locked {
		return ErrVaultLocked
	}

	keys, err := ListSSHKeys(ctx, tk.mock)
	if err != nil {
		return err
	}

	tk.mu.Lock()
	tk.keys = keys
	tk.mu.Unlock()

	return nil
}

func TestKeyring_List_EmptyVault(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)
	if err := tk.refreshKeysFromMock(context.Background()); err != nil {
		t.Fatalf("refreshKeysFromMock() error = %v", err)
	}

	// Since we can't easily mock the full Keyring.List, test the underlying keys
	tk.mu.RLock()
	defer tk.mu.RUnlock()

	if len(tk.keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(tk.keys))
	}
}

func TestKeyring_List_WithKeys(t *testing.T) {
	items := []bitwarden.Item{
		{
			ID:   "key1",
			Name: "Test Key 1",
			Type: bitwarden.ItemTypeSSHKey,
			SSHKey: &bitwarden.SSHKey{
				PrivateKey:     testED25519PrivateKey,
				PublicKey:      testED25519PublicKey,
				KeyFingerprint: "SHA256:test1",
			},
		},
		{
			ID:   "login1",
			Name: "Test Login",
			Type: bitwarden.ItemTypeLogin,
		},
	}

	tk := newTestableKeyring(items, false)
	if err := tk.refreshKeysFromMock(context.Background()); err != nil {
		t.Fatalf("refreshKeysFromMock() error = %v", err)
	}

	tk.mu.RLock()
	defer tk.mu.RUnlock()

	// Should only have 1 SSH key, not the login item
	if len(tk.keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(tk.keys))
	}

	if tk.keys[0].Item.Name != "Test Key 1" {
		t.Errorf("Expected key name 'Test Key 1', got '%s'", tk.keys[0].Item.Name)
	}
}

func TestKeyring_ReadOnlyOperations(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	// Add should return ErrReadOnly
	err := tk.Add(agent.AddedKey{})
	if err != ErrReadOnly {
		t.Errorf("Add() error = %v, want %v", err, ErrReadOnly)
	}

	// Remove should return ErrReadOnly
	err = tk.Remove(nil)
	if err != ErrReadOnly {
		t.Errorf("Remove() error = %v, want %v", err, ErrReadOnly)
	}

	// RemoveAll should return ErrReadOnly
	err = tk.RemoveAll()
	if err != ErrReadOnly {
		t.Errorf("RemoveAll() error = %v, want %v", err, ErrReadOnly)
	}
}

func TestKeyring_Extension(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	_, err := tk.Extension("test", nil)
	if err != agent.ErrExtensionUnsupported {
		t.Errorf("Extension() error = %v, want %v", err, agent.ErrExtensionUnsupported)
	}
}
