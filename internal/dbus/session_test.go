package dbus

import (
	"bytes"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/crypto"
)

// mockSessionExport is a controllable export function for testing sessions
type mockSessionExport struct {
	shouldFail bool
	callCount  int
}

func (m *mockSessionExport) export(session *Session) error {
	m.callCount++
	if m.shouldFail {
		return dbus.Error{Name: "test.error", Body: []interface{}{"export failed"}}
	}
	return nil
}

func TestCreateSession_Plain(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	session, output, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession(plain) failed: %v", err)
	}

	// Verify session was stored
	retrieved, ok := sm.GetSession(session.path)
	if !ok {
		t.Error("session not found in manager")
	}
	if retrieved != session {
		t.Error("retrieved session is not the same object")
	}

	// Verify algorithm is plain
	if session.algorithm != AlgorithmPlain {
		t.Errorf("algorithm = %q, want %q", session.algorithm, AlgorithmPlain)
	}

	// Verify session path is returned and has correct prefix
	if !bytes.HasPrefix([]byte(session.path), []byte(SessionPath)) {
		t.Errorf("session path %q does not have prefix %q", session.path, SessionPath)
	}

	// Output should be empty string for plain
	if output.Value() != "" {
		t.Errorf("output = %v, want empty string", output.Value())
	}

	// Export should be called
	if mockExport.callCount != 1 {
		t.Errorf("export called %d times, expected 1", mockExport.callCount)
	}
}

func TestCreateSession_DH(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	// Generate a valid client public key for DH exchange
	// We use crypto.GenerateDHKeyPair to create a key pair, then use its public key
	// as the "peer" public key for the server
	dummyKeyPair, err := crypto.GenerateDHKeyPair([]byte{0x02}) // Simple valid public key
	if err != nil {
		t.Fatalf("failed to generate dummy key pair: %v", err)
	}

	// Generate client's own key pair
	clientKeyPair, err := crypto.GenerateDHKeyPair(dummyKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate client key pair: %v", err)
	}

	session, output, err := sm.CreateSession(AlgorithmDH, clientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("CreateSession(DH) failed: %v", err)
	}

	// Verify session was stored
	retrieved, ok := sm.GetSession(session.path)
	if !ok {
		t.Error("session not found in manager")
	}
	if retrieved != session {
		t.Error("retrieved session is not the same object")
	}

	// Verify algorithm is DH
	if session.algorithm != AlgorithmDH {
		t.Errorf("algorithm = %q, want %q", session.algorithm, AlgorithmDH)
	}

	// Verify session path is returned
	if !bytes.HasPrefix([]byte(session.path), []byte(SessionPath)) {
		t.Errorf("session path %q does not have prefix %q", session.path, SessionPath)
	}

	// Output (server public key) should be non-empty
	serverPubKey, ok := output.Value().([]byte)
	if !ok {
		t.Fatalf("output is not []byte, got %T", output.Value())
	}
	if len(serverPubKey) == 0 {
		t.Error("server public key is empty")
	}

	// Verify the server public key is valid DH key size
	if len(serverPubKey) != crypto.DHKeyBytes {
		t.Errorf("server public key length = %d, want %d", len(serverPubKey), crypto.DHKeyBytes)
	}

	// Export should be called
	if mockExport.callCount != 1 {
		t.Errorf("export called %d times, expected 1", mockExport.callCount)
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	// Generate client's key pair
	dummyKeyPair, err := crypto.GenerateDHKeyPair([]byte{0x02})
	if err != nil {
		t.Fatalf("failed to generate dummy key pair: %v", err)
	}
	clientKeyPair, err := crypto.GenerateDHKeyPair(dummyKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate client key pair: %v", err)
	}

	// Create server session (this generates server's key pair and derives AES key)
	session, output, err := sm.CreateSession(AlgorithmDH, clientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("CreateSession(DH) failed: %v", err)
	}

	serverPubKey := output.Value().([]byte)

	// Client derives shared secret from server's public key
	sharedSecret, err := clientKeyPair.ComputeSharedSecret(serverPubKey)
	if err != nil {
		t.Fatalf("failed to compute shared secret: %v", err)
	}

	// Client derives AES key
	clientAESKey, err := crypto.DeriveAESKey(sharedSecret)
	if err != nil {
		t.Fatalf("failed to derive client AES key: %v", err)
	}

	// Original secret value
	originalValue := []byte("my secret password")

	// Client encrypts the secret
	ciphertext, iv, err := crypto.Encrypt(originalValue, clientAESKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Server decrypts using the session
	decrypted, err := session.DecryptSecret(ciphertext, iv)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	// Verify decrypted value matches original
	if !bytes.Equal(decrypted, originalValue) {
		t.Errorf("decrypted value = %q, want %q", decrypted, originalValue)
	}

	// Test reverse: server encrypts, client decrypts
	serverPlaintext := []byte("server's secret message")
	serverCiphertext, serverIV, err := session.EncryptSecret(serverPlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt with session: %v", err)
	}

	// Client decrypts
	clientDecrypted, err := crypto.Decrypt(serverCiphertext, clientAESKey, serverIV)
	if err != nil {
		t.Fatalf("failed to decrypt on client: %v", err)
	}

	if !bytes.Equal(clientDecrypted, serverPlaintext) {
		t.Errorf("client decrypted value = %q, want %q", clientDecrypted, serverPlaintext)
	}
}

func TestGetSessionOrError(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	// Create a session first
	session, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Test with valid session ID
	retrieved, dbusErr := sm.GetSessionOrError(session.path)
	if dbusErr != nil {
		t.Errorf("GetSessionOrError(valid) returned error: %v", dbusErr)
	}
	if retrieved != session {
		t.Error("GetSessionOrError returned different session")
	}

	// Test with invalid session ID
	invalidPath := dbus.ObjectPath("/org/freedesktop/secrets/session/99999")
	retrieved, dbusErr = sm.GetSessionOrError(invalidPath)
	if dbusErr == nil {
		t.Error("GetSessionOrError(invalid) should return error")
	}
	if retrieved != nil {
		t.Error("GetSessionOrError(invalid) should return nil session")
	}
	if dbusErr != nil && dbusErr.Name != ErrNoSession {
		t.Errorf("error name = %q, want %q", dbusErr.Name, ErrNoSession)
	}
}

func TestCreateSession_ExportFailure(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{shouldFail: true}
	sm.exportFunc = mockExport.export

	_, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err == nil {
		t.Error("CreateSession should fail when export fails")
	}

	// Verify session was not stored
	if sm.SessionCount() != 0 {
		t.Error("session should not be stored when export fails")
	}
}

func TestCreateSession_CounterIncrement(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	session1, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	session2, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	session3, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Verify paths are unique
	paths := map[dbus.ObjectPath]bool{
		session1.path: true,
		session2.path: true,
		session3.path: true,
	}
	if len(paths) != 3 {
		t.Error("session paths should be unique")
	}
}

func TestSession_Close(t *testing.T) {
	// Note: This test verifies the session is removed from the manager.
	// The actual D-Bus unexport is mocked out since we don't have a real D-Bus connection.
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export
	// Mock the unexport function to avoid needing a real D-Bus connection
	sm.unexportFunc = func(conn *dbus.Conn, path dbus.ObjectPath, iface string, all bool) {}

	session, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	path := session.path

	// Verify session exists before closing
	_, exists := sm.GetSession(path)
	if !exists {
		t.Fatal("session should exist before calling Close")
	}

	// Use CloseSession to properly remove the session
	if err := sm.CloseSession(path); err != nil {
		t.Fatalf("CloseSession failed: %v", err)
	}

	// Verify session is removed
	_, exists = sm.GetSession(path)
	if exists {
		t.Error("session should be removed after calling CloseSession")
	}
}

func TestSession_PlainEncryption(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	session, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Test encryption with plain session (should return plaintext)
	plaintext := []byte("test data")
	ciphertext, params, err := session.EncryptSecret(plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	// For plain session, ciphertext should be same as plaintext
	if !bytes.Equal(ciphertext, plaintext) {
		t.Error("plain session should return plaintext as ciphertext")
	}
	if len(params) != 0 {
		t.Error("plain session should return empty params")
	}

	// Test decryption with plain session
	decrypted, err := session.DecryptSecret(ciphertext, params)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted value should match plaintext for plain session")
	}
}

func TestSession_Properties(t *testing.T) {
	sm := NewSessionManager(nil)
	mockExport := &mockSessionExport{}
	sm.exportFunc = mockExport.export

	// Test plain session properties
	plainSession, _, err := sm.CreateSession(AlgorithmPlain, []byte{})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if plainSession.Algorithm() != AlgorithmPlain {
		t.Errorf("Algorithm() = %q, want %q", plainSession.Algorithm(), AlgorithmPlain)
	}
	if plainSession.IsEncrypted() {
		t.Error("plain session should not be encrypted")
	}

	// Test DH session properties
	dummyKeyPair, err := crypto.GenerateDHKeyPair([]byte{0x02})
	if err != nil {
		t.Fatalf("GenerateDHKeyPair failed: %v", err)
	}
	clientKeyPair, err := crypto.GenerateDHKeyPair(dummyKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("GenerateDHKeyPair failed: %v", err)
	}
	dhSession, _, err := sm.CreateSession(AlgorithmDH, clientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if dhSession.Algorithm() != AlgorithmDH {
		t.Errorf("Algorithm() = %q, want %q", dhSession.Algorithm(), AlgorithmDH)
	}
	if !dhSession.IsEncrypted() {
		t.Error("DH session should be encrypted")
	}

	// Test Path()
	if plainSession.Path() != plainSession.path {
		t.Error("Path() should return session's path")
	}
}

func TestSession_DHInvalidKey(t *testing.T) {
	sm := NewSessionManager(nil)

	// Test with invalid public key (too short)
	_, _, err := sm.CreateSession(AlgorithmDH, []byte{0x01})
	if err == nil {
		t.Error("CreateSession should fail with invalid public key")
	}

	// Test with empty public key
	_, _, err = sm.CreateSession(AlgorithmDH, []byte{})
	if err == nil {
		t.Error("CreateSession should fail with empty public key")
	}
}

func TestSession_DHDecryptWithoutKey(t *testing.T) {
	// Create a session with nil aesKey to test error handling
	session := &Session{
		conn:      nil,
		path:      dbus.ObjectPath(SessionPath + "test"),
		algorithm: AlgorithmDH,
		aesKey:    nil, // Simulate uninitialized key
	}

	_, err := session.DecryptSecret([]byte("data"), []byte("iv"))
	if err == nil {
		t.Error("DecryptSecret should fail when aesKey is nil")
	}

	_, _, err = session.EncryptSecret([]byte("data"))
	if err == nil {
		t.Error("EncryptSecret should fail when aesKey is nil")
	}
}

func TestCloseSession_NotFound(t *testing.T) {
	sm := NewSessionManager(nil)

	invalidPath := dbus.ObjectPath("/org/freedesktop/secrets/session/99999")
	err := sm.CloseSession(invalidPath)
	if err == nil {
		t.Error("CloseSession should return error for non-existent session")
	}
}
