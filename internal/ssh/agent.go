package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh/agent"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/logging"
)

// Server manages the SSH agent Unix socket and handles incoming connections.
type Server struct {
	socketPath string
	keyring    *Keyring
	listener   net.Listener
	mu         sync.Mutex
	done       chan struct{}
	wg         sync.WaitGroup
	debug      bool
	started    bool                  // tracks if server is running
	conns      map[net.Conn]struct{} // active connections
	connsMu    sync.Mutex            // protects conns map
}

// NewServer creates a new SSH agent server.
func NewServer(socketPath string, client *bitwarden.Client) *Server {
	return &Server{
		socketPath: socketPath,
		keyring:    NewKeyring(client),
	}
}

// SetDebug enables or disables debug logging.
func (s *Server) SetDebug(debug bool) {
	s.debug = debug
	s.keyring.SetDebug(debug)
}

// SocketPath returns the path to the Unix socket.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Start starts the SSH agent server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prevent double-start
	if s.started {
		return ErrAlreadyStarted
	}

	// Initialize/recreate channels and maps for (re)start
	s.done = make(chan struct{})
	s.conns = make(map[net.Conn]struct{})

	// Create socket directory if needed
	socketDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Security validation: ensure socket directory is not a symlink, is owned by current user,
	// and has restrictive permissions
	if err := validateSocketDir(socketDir); err != nil {
		return err
	}

	// Remove stale socket if it exists
	if info, err := os.Stat(s.socketPath); err == nil {
		// Verify it's actually a socket before attempting removal
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%w: %s", ErrNotSocket, s.socketPath)
		}

		// Try to connect to see if it's in use
		conn, err := net.Dial("unix", s.socketPath)
		if err == nil {
			conn.Close()
			return fmt.Errorf("%w: socket is in use", ErrSocketExists)
		}
		// Socket exists but not in use - remove it
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("failed to remove stale socket: %w", err)
		}
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		os.Remove(s.socketPath)
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	if s.debug {
		logging.L.With("component", "ssh-agent").Info("listening on socket", "path", s.socketPath)
	}

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	s.started = true
	return nil
}

// validateSocketDir validates that the socket directory is secure:
// - Not a symlink (to prevent symlink attacks)
// - Owned by the current user
// - Has restrictive permissions (no world/group access)
func validateSocketDir(dir string) error {
	// Lstat to check if it's a symlink
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat socket directory: %w", err)
	}

	// Check for symlink
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecureSocketDir, dir)
	}

	// Check ownership
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// On systems where Stat_t is not available, skip ownership check
		// but still check permissions
	} else {
		if int(stat.Uid) != os.Geteuid() {
			return fmt.Errorf("%w: %s is not owned by current user", ErrInsecureSocketDir, dir)
		}
	}

	// Check permissions - reject if world or group has any access
	perm := fi.Mode().Perm()
	if perm&0077 != 0 {
		// Try to fix permissions first
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("%w: %s has permissions %04o and chmod failed: %w", ErrInsecureSocketDir, dir, perm, err)
		}
		// Re-check permissions after chmod
		fi, err = os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("failed to re-stat socket directory after chmod: %w", err)
		}
		if fi.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("%w: %s has permissions %04o (chmod to 0700 failed)", ErrInsecureSocketDir, dir, fi.Mode().Perm())
		}
	}

	return nil
}

// acceptLoop accepts incoming connections and spawns handlers.
func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Check if we're shutting down
			select {
			case <-s.done:
				return
			case <-ctx.Done():
				return
			default:
				if s.debug {
					logging.L.With("component", "ssh-agent").Warn("accept error", "error", err)
				}
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SSH agent connection.
func (s *Server) handleConnection(conn net.Conn) {
	// Track this connection
	s.connsMu.Lock()
	s.conns[conn] = struct{}{}
	s.connsMu.Unlock()

	defer func() {
		s.connsMu.Lock()
		delete(s.conns, conn)
		s.connsMu.Unlock()
		conn.Close()
		s.wg.Done()
	}()

	if s.debug {
		logging.L.With("component", "ssh-agent").Info("new connection", "remote", conn.RemoteAddr())
	}

	// ServeAgent serves the agent protocol on the connection
	if err := agent.ServeAgent(s.keyring, conn); err != nil {
		if s.debug {
			logging.L.With("component", "ssh-agent").Warn("connection error", "error", err)
		}
	}
}

// Stop stops the SSH agent server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Already stopped or never started
	if !s.started {
		return nil
	}

	// Signal done
	select {
	case <-s.done:
		// Already closed
	default:
		close(s.done)
	}

	// Close listener to stop accepting new connections
	if s.listener != nil {
		s.listener.Close()
	}

	// Close all active connections to unblock handlers
	s.connsMu.Lock()
	for conn := range s.conns {
		conn.Close()
	}
	s.connsMu.Unlock()

	// Wait for all connections to finish
	s.wg.Wait()

	// Remove socket file
	if s.socketPath != "" {
		os.Remove(s.socketPath)
	}

	s.started = false

	if s.debug {
		logging.L.With("component", "ssh-agent").Info("stopped")
	}

	return nil
}

// Keyring returns the underlying keyring.
func (s *Server) Keyring() *Keyring {
	return s.keyring
}
