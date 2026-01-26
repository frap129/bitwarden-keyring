package dbus

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
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
	aesKey    []byte // AES key for encrypted sessions (nil for plain)
}

// SessionManager manages active sessions
type SessionManager struct {
	conn     *dbus.Conn
	sessions map[dbus.ObjectPath]*Session
	counter  uint64
	mu       sync.RWMutex
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
		// DH key exchange
		group := rfc2409SecondOakleyGroup()
		private, public, err := group.NewKeypair()
		if err != nil {
			return nil, dbus.Variant{}, fmt.Errorf("DH keypair generation failed: %w", err)
		}

		// Output is our public key (big-endian bytes)
		output = dbus.MakeVariant(public.Bytes())

		// Parse client's public key
		theirPublic := new(big.Int)
		theirPublic.SetBytes(input)

		// Derive AES key from shared secret
		aesKey, err = group.keygenHKDFSHA256AES128(theirPublic, private)
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
	}

	sm.mu.Lock()
	sm.sessions[path] = session
	sm.mu.Unlock()

	// Export the session object
	if err := sm.exportSession(session); err != nil {
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

// CloseSession closes and removes a session
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

	// Unexport the session object
	sm.conn.Export(nil, session.path, SessionInterface)

	return nil
}

// exportSession exports a session object to D-Bus
func (sm *SessionManager) exportSession(session *Session) error {
	// Export the session methods
	err := sm.conn.Export(session, session.path, SessionInterface)
	if err != nil {
		return err
	}

	// Export introspection
	err = sm.conn.Export(
		introspectable(SessionIntrospectXML),
		session.path,
		"org.freedesktop.DBus.Introspectable",
	)
	if err != nil {
		return err
	}

	return nil
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

	iv, ciphertext, err := aescbcEncrypt(plaintext, s.aesKey)
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

	return aescbcDecrypt(parameters, ciphertext, s.aesKey)
}

// Close closes the session (D-Bus method)
func (s *Session) Close() *dbus.Error {
	// The actual cleanup is handled by SessionManager
	return nil
}

// introspectable implements the Introspectable interface
type introspectable string

func (i introspectable) Introspect() (string, *dbus.Error) {
	return string(i), nil
}
