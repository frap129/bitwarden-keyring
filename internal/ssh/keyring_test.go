package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// mockBitwardenClient implements BitwardenClient for testing
type mockBitwardenClient struct {
	items         []bitwarden.Item
	locked        bool
	unlocked      bool
	createCalls   int
	deleteCalls   int
	deleteItemIDs []string
}

func (m *mockBitwardenClient) ListItems(ctx context.Context) ([]bitwarden.Item, error) {
	if m.locked {
		return nil, bitwarden.ErrVaultLocked
	}
	return m.items, nil
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

func (m *mockBitwardenClient) CreateItem(ctx context.Context, req bitwarden.CreateItemRequest) (*bitwarden.Item, error) {
	if m.locked {
		return nil, bitwarden.ErrVaultLocked
	}
	m.createCalls++
	item := &bitwarden.Item{
		ID:     "new-item-id",
		Name:   req.Name,
		Type:   req.Type,
		SSHKey: req.SSHKey,
	}
	m.items = append(m.items, *item)
	return item, nil
}

func (m *mockBitwardenClient) DeleteItem(ctx context.Context, id string) error {
	if m.locked {
		return bitwarden.ErrVaultLocked
	}
	m.deleteCalls++
	m.deleteItemIDs = append(m.deleteItemIDs, id)
	// Remove from items
	newItems := make([]bitwarden.Item, 0, len(m.items))
	for _, item := range m.items {
		if item.ID != id {
			newItems = append(newItems, item)
		}
	}
	m.items = newItems
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

	// Create a Keyring with the mock client
	kr := &Keyring{
		client: mock,
	}

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

	result, err := ListSSHKeys(ctx, tk.mock)
	if err != nil {
		return err
	}

	tk.mu.Lock()
	tk.keys = result.Keys
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

func TestKeyring_Add(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	// Generate a test key
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Add a key
	err = tk.Add(agent.AddedKey{
		PrivateKey: priv,
		Comment:    "test-key",
	})
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Verify CreateItem was called
	if tk.mock.createCalls != 1 {
		t.Errorf("Expected 1 CreateItem call, got %d", tk.mock.createCalls)
	}

	// Verify the item was added to mock
	if len(tk.mock.items) != 1 {
		t.Errorf("Expected 1 item in mock, got %d", len(tk.mock.items))
	}

	if tk.mock.items[0].Name != "test-key" {
		t.Errorf("Expected item name 'test-key', got '%s'", tk.mock.items[0].Name)
	}
}

func TestKeyring_Add_Duplicate(t *testing.T) {
	// Generate a key that we'll treat as already existing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a signer to get the fingerprint
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Marshal the private key for the mock item
	privPEM, err := marshalPrivateKeyOpenSSH(priv, "existing-key")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	pubKey := signer.PublicKey()
	fingerprint := cryptossh.FingerprintSHA256(pubKey)

	// Start with an existing key in the vault
	items := []bitwarden.Item{
		{
			ID:   "key1",
			Name: "Existing Key",
			Type: bitwarden.ItemTypeSSHKey,
			SSHKey: &bitwarden.SSHKey{
				PrivateKey:     string(privPEM),
				PublicKey:      formatAuthorizedKey(pubKey, "existing-key"),
				KeyFingerprint: fingerprint,
			},
		},
	}

	tk := newTestableKeyring(items, false)

	// Refresh the keys to populate the cache with the existing key
	if err := tk.refreshKeysFromMock(context.Background()); err != nil {
		t.Fatalf("failed to refresh keys: %v", err)
	}

	// Try to add the same key again (using the raw ed25519 private key)
	err = tk.Add(agent.AddedKey{
		PrivateKey: priv,
		Comment:    "duplicate-key",
	})
	if err != nil {
		t.Fatalf("Add() error = %v, expected idempotent success", err)
	}

	// Verify CreateItem was NOT called (key already exists)
	if tk.mock.createCalls != 0 {
		t.Errorf("Expected 0 CreateItem calls for duplicate, got %d", tk.mock.createCalls)
	}

	// Also ensure we can find both keys (they're the same)
	_ = pub // use pub to avoid unused variable error
}

func TestKeyring_Add_VaultLocked(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, true) // locked = true

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err = tk.Add(agent.AddedKey{
		PrivateKey: priv,
		Comment:    "test-key",
	})
	if !errors.Is(err, bitwarden.ErrVaultLocked) {
		t.Errorf("Add() error = %v, want error containing %v", err, bitwarden.ErrVaultLocked)
	}

	// Verify CreateItem was not called
	if tk.mock.createCalls != 0 {
		t.Errorf("Expected 0 CreateItem calls, got %d", tk.mock.createCalls)
	}
}

func TestKeyring_Add_NilKey(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	err := tk.Add(agent.AddedKey{})
	if err == nil {
		t.Error("Add() with nil key should return error")
	}
}

func TestKeyring_Remove(t *testing.T) {
	// Start with an existing key
	items := []bitwarden.Item{
		{
			ID:   "key1",
			Name: "Test Key",
			Type: bitwarden.ItemTypeSSHKey,
			SSHKey: &bitwarden.SSHKey{
				PrivateKey:     testED25519PrivateKey,
				PublicKey:      testED25519PublicKey,
				KeyFingerprint: "SHA256:test1",
			},
		},
	}

	tk := newTestableKeyring(items, false)

	// Parse the key to get the public key
	signer, err := cryptossh.ParsePrivateKey([]byte(testED25519PrivateKey))
	if err != nil {
		t.Fatalf("failed to parse test key: %v", err)
	}

	// Remove the key
	err = tk.Remove(signer.PublicKey())
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	// Verify DeleteItem was called
	if tk.mock.deleteCalls != 1 {
		t.Errorf("Expected 1 DeleteItem call, got %d", tk.mock.deleteCalls)
	}

	// Verify the correct item was deleted
	if len(tk.mock.deleteItemIDs) != 1 || tk.mock.deleteItemIDs[0] != "key1" {
		t.Errorf("Expected deletion of 'key1', got %v", tk.mock.deleteItemIDs)
	}
}

func TestKeyring_Remove_NotFound(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	// Generate a random key that doesn't exist in the vault
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	err = tk.Remove(signer.PublicKey())
	if err != ErrKeyNotFound {
		t.Errorf("Remove() error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestKeyring_Remove_VaultLocked(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, true) // locked = true

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	err = tk.Remove(signer.PublicKey())
	if !errors.Is(err, bitwarden.ErrVaultLocked) {
		t.Errorf("Remove() error = %v, want error containing %v", err, bitwarden.ErrVaultLocked)
	}
}

func TestKeyring_RemoveAll_NotSupported(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	// RemoveAll should return ErrRemoveAllNotSupported
	err := tk.RemoveAll()
	if err != ErrRemoveAllNotSupported {
		t.Errorf("RemoveAll() error = %v, want %v", err, ErrRemoveAllNotSupported)
	}
}

func TestKeyring_Extension(t *testing.T) {
	tk := newTestableKeyring([]bitwarden.Item{}, false)

	_, err := tk.Extension("test", nil)
	if err != agent.ErrExtensionUnsupported {
		t.Errorf("Extension() error = %v, want %v", err, agent.ErrExtensionUnsupported)
	}
}
