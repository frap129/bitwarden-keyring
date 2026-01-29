package ssh

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh/agent"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
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
}

// NewServer creates a new SSH agent server.
func NewServer(socketPath string, client *bitwarden.Client) *Server {
	return &Server{
		socketPath: socketPath,
		keyring:    NewKeyring(client),
		done:       make(chan struct{}),
	}
}

// SetDebug enables or disables debug logging.
func (s *Server) SetDebug(debug bool) {
	s.debug = debug
}

// SocketPath returns the path to the Unix socket.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// Start starts the SSH agent server.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create socket directory if needed
	socketDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove stale socket if it exists
	if _, err := os.Stat(s.socketPath); err == nil {
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
		log.Printf("SSH agent listening on %s", s.socketPath)
	}

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	return nil
}

// acceptLoop accepts incoming connections and spawns handlers.
func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-s.done:
			return
		case <-ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			case <-ctx.Done():
				return
			default:
				if s.debug {
					log.Printf("SSH agent accept error: %v", err)
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
	defer s.wg.Done()
	defer conn.Close()

	if s.debug {
		log.Printf("SSH agent: new connection from %s", conn.RemoteAddr())
	}

	// ServeAgent serves the agent protocol on the connection
	if err := agent.ServeAgent(s.keyring, conn); err != nil {
		if s.debug {
			log.Printf("SSH agent: connection error: %v", err)
		}
	}
}

// Stop stops the SSH agent server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Signal done
	select {
	case <-s.done:
		// Already closed
	default:
		close(s.done)
	}

	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}

	// Wait for all connections to finish
	s.wg.Wait()

	// Remove socket file
	if s.socketPath != "" {
		os.Remove(s.socketPath)
	}

	if s.debug {
		log.Printf("SSH agent stopped")
	}

	return nil
}

// Keyring returns the underlying keyring.
func (s *Server) Keyring() *Keyring {
	return s.keyring
}
