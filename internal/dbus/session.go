package dbus

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/crypto"
)

const (
	AlgorithmPlain = "plain"
	AlgorithmDH    = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

// Session represents a D-Bus session for secret transfer
type Session struct {
	conn      *dbus.Conn
	path      dbus.ObjectPath
	algorithm string
	aesKey    []byte          // AES key for encrypted sessions (nil for plain)
	manager   *SessionManager // back-reference for cleanup
}

// SessionManager manages active sessions
type SessionManager struct {
	conn         *dbus.Conn
	sessions     map[dbus.ObjectPath]*Session
	counter      uint64
	mu           sync.RWMutex
	exportFunc   func(*Session) error                            // for testing; defaults to exportSession
	unexportFunc func(*dbus.Conn, dbus.ObjectPath, string, bool) // for testing; defaults to unexportDBusObject
}

// NewSessionManager creates a new session manager
func NewSessionManager(conn *dbus.Conn) *SessionManager {
	return &SessionManager{
		conn:     conn,
		sessions: make(map[dbus.ObjectPath]*Session),
	}
}

// CreateSession creates a new session with the given algorithm
// input is the client's DH public key for encrypted sessions
func (sm *SessionManager) CreateSession(algorithm string, input []byte) (*Session, dbus.Variant, error) {
	id := atomic.AddUint64(&sm.counter, 1)
	path := dbus.ObjectPath(fmt.Sprintf("%s%d", SessionPath, id))

	var aesKey []byte
	var output dbus.Variant

	switch algorithm {
	case AlgorithmPlain:
		// Plain algorithm - no encryption, output is empty string
		output = dbus.MakeVariant("")

	case AlgorithmDH:
		// DH key exchange using the crypto package
		dhPair, err := crypto.GenerateDHKeyPair(input)
		if err != nil {
			return nil, dbus.Variant{}, fmt.Errorf("DH key exchange failed: %w", err)
		}

		// Output is our public key
		output = dbus.MakeVariant(dhPair.PublicKey)

		// Derive AES key from shared secret
		aesKey, err = crypto.DeriveAESKey(dhPair.SharedKey)
		if err != nil {
			return nil, dbus.Variant{}, fmt.Errorf("key derivation failed: %w", err)
		}

	default:
		return nil, dbus.Variant{}, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	session := &Session{
		conn:      sm.conn,
		path:      path,
		algorithm: algorithm,
		aesKey:    aesKey,
		manager:   sm, // back-reference for cleanup
	}

	sm.mu.Lock()
	sm.sessions[path] = session
	sm.mu.Unlock()

	// Export the session object
	exportFn := sm.exportFunc
	if exportFn == nil {
		exportFn = sm.exportSession
	}
	if err := exportFn(session); err != nil {
		sm.mu.Lock()
		delete(sm.sessions, path)
		sm.mu.Unlock()
		return nil, dbus.Variant{}, err
	}

	return session, output, nil
}

// GetSession retrieves a session by path
func (sm *SessionManager) GetSession(path dbus.ObjectPath) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, ok := sm.sessions[path]
	return session, ok
}

// GetSessionOrError retrieves a session by path or returns a D-Bus error.
// This is a convenience wrapper for D-Bus methods that need to validate sessions.
func (sm *SessionManager) GetSessionOrError(path dbus.ObjectPath) (*Session, *dbus.Error) {
	session, ok := sm.GetSession(path)
	if !ok {
		return nil, &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}
	return session, nil
}

// SessionCount returns the number of active sessions.
// This is safe for concurrent use.
func (sm *SessionManager) SessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// CloseSession closes and removes a session, unexports all D-Bus interfaces
func (sm *SessionManager) CloseSession(path dbus.ObjectPath) error {
	sm.mu.Lock()
	session, ok := sm.sessions[path]
	if ok {
		delete(sm.sessions, path)
	}
	sm.mu.Unlock()

	if !ok {
		return fmt.Errorf("session not found: %s", path)
	}

	// Unexport all session D-Bus interfaces
	unexportFn := sm.unexportFunc
	if unexportFn == nil {
		unexportFn = unexportDBusObject
	}
	unexportFn(sm.conn, session.path, SessionInterface, false)

	return nil
}

// exportSession exports a session object to D-Bus
func (sm *SessionManager) exportSession(session *Session) error {
	return exportDBusObject(sm.conn, session, session.path, SessionInterface, SessionIntrospectXML, false)
}

// Path returns the session's object path
func (s *Session) Path() dbus.ObjectPath {
	return s.path
}

// Algorithm returns the session's algorithm
func (s *Session) Algorithm() string {
	return s.algorithm
}

// IsEncrypted returns whether this session uses encryption
func (s *Session) IsEncrypted() bool {
	return s.algorithm == AlgorithmDH
}

// EncryptSecret encrypts a secret value for transmission
// Returns (value, parameters) where parameters is the IV for DH sessions
func (s *Session) EncryptSecret(plaintext []byte) ([]byte, []byte, error) {
	if s.algorithm == AlgorithmPlain {
		return plaintext, []byte{}, nil
	}

	if s.aesKey == nil {
		return nil, nil, fmt.Errorf("session not initialized for encryption")
	}

	ciphertext, iv, err := crypto.Encrypt(plaintext, s.aesKey)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, iv, nil
}

// DecryptSecret decrypts a secret value received from client
// parameters is the IV for DH sessions
func (s *Session) DecryptSecret(ciphertext, parameters []byte) ([]byte, error) {
	if s.algorithm == AlgorithmPlain {
		return ciphertext, nil
	}

	if s.aesKey == nil {
		return nil, fmt.Errorf("session not initialized for decryption")
	}

	return crypto.Decrypt(ciphertext, s.aesKey, parameters)
}

// Close closes the session (D-Bus method)
func (s *Session) Close() *dbus.Error {
	if s.manager != nil {
		_ = s.manager.CloseSession(s.path)
	}
	return nil
}

// introspectable implements the Introspectable interface
type introspectable string

func (i introspectable) Introspect() (string, *dbus.Error) {
	return string(i), nil
}
