package dbus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/logging"
)

// Prompt represents an unlock prompt
type Prompt struct {
	conn      *dbus.Conn
	path      dbus.ObjectPath
	bwClient  *bitwarden.Client
	objects   []dbus.ObjectPath
	done      bool
	mu        sync.Mutex
	startOnce sync.Once
	manager   *PromptManager     // back-reference for cleanup
	cancel    context.CancelFunc // cancel function to stop in-flight operations
}

// PromptManager manages prompt objects
type PromptManager struct {
	conn     *dbus.Conn
	bwClient *bitwarden.Client
	prompts  map[dbus.ObjectPath]*Prompt
	counter  uint64
	mu       sync.RWMutex
}

// NewPromptManager creates a new prompt manager
func NewPromptManager(conn *dbus.Conn, bwClient *bitwarden.Client) *PromptManager {
	return &PromptManager{
		conn:     conn,
		bwClient: bwClient,
		prompts:  make(map[dbus.ObjectPath]*Prompt),
	}
}

// CreateUnlockPrompt creates a prompt for unlocking
func (pm *PromptManager) CreateUnlockPrompt(objects []dbus.ObjectPath) (*Prompt, error) {
	id := atomic.AddUint64(&pm.counter, 1)
	path := dbus.ObjectPath(fmt.Sprintf("%s%d", PromptPath, id))

	prompt := &Prompt{
		conn:     pm.conn,
		path:     path,
		bwClient: pm.bwClient,
		objects:  objects,
		manager:  pm, // back-reference for cleanup
	}

	pm.mu.Lock()
	pm.prompts[path] = prompt
	pm.mu.Unlock()

	if err := pm.exportPrompt(prompt); err != nil {
		pm.mu.Lock()
		delete(pm.prompts, path)
		pm.mu.Unlock()
		return nil, err
	}

	return prompt, nil
}

// exportPrompt exports a prompt to D-Bus
func (pm *PromptManager) exportPrompt(prompt *Prompt) error {
	return exportDBusObject(pm.conn, prompt, prompt.path, PromptInterface, PromptIntrospectXML, false)
}

// RemovePrompt removes a prompt and unexports all its D-Bus interfaces
func (pm *PromptManager) RemovePrompt(path dbus.ObjectPath) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, ok := pm.prompts[path]; ok {
		unexportDBusObject(pm.conn, path, PromptInterface, false)
		delete(pm.prompts, path)
	}
}

// Path returns the prompt's object path
func (p *Prompt) Path() dbus.ObjectPath {
	return p.path
}

// Prompt triggers the prompt (D-Bus method)
func (p *Prompt) Prompt(windowID string) *dbus.Error {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	// Use sync.Once to ensure only one unlock goroutine starts
	p.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		p.mu.Lock()
		p.cancel = cancel
		p.mu.Unlock()
		go p.doUnlock(ctx)
	})

	return nil
}

// Dismiss dismisses the prompt (D-Bus method)
func (p *Prompt) Dismiss() *dbus.Error {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return nil
	}
	p.done = true
	cancel := p.cancel
	p.mu.Unlock()

	// Cancel any in-flight operations
	if cancel != nil {
		cancel()
	}

	// Emit Completed signal with dismissed=true
	p.emitCompleted(true, nil)

	// Cleanup: remove from manager and unexport
	if p.manager != nil {
		p.manager.RemovePrompt(p.path)
	}

	return nil
}

// doUnlock performs the actual unlock operation
func (p *Prompt) doUnlock(ctx context.Context) {
	// ListItems triggers auto-unlock in the client
	// We don't need the result, just the unlock side-effect
	_, err := p.bwClient.ListItems(ctx)
	if err != nil {
		// Check if context was cancelled (dismiss was called)
		if errors.Is(err, context.Canceled) {
			logging.L.With("component", "dbus").Debug("prompt unlock cancelled")
			return // Dismiss already handled completion
		}
		// Log the error for debugging (D-Bus signal can't carry error details)
		if errors.Is(err, bitwarden.ErrUserCancelled) {
			logging.L.With("component", "dbus").Info("prompt unlock dismissed by user")
		} else {
			logging.L.With("component", "dbus").Warn("prompt unlock failed", "error", err)
		}

		p.completeOnce(true, nil) // Dismissed/failed
		return
	}

	p.mu.Lock()
	objects := p.objects
	p.mu.Unlock()

	// Emit Completed signal with the unlocked objects
	p.completeOnce(false, objects)
}

// completeOnce completes the prompt exactly once, emitting the signal and cleaning up
func (p *Prompt) completeOnce(dismissed bool, objects []dbus.ObjectPath) {
	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		return
	}
	p.done = true
	p.mu.Unlock()

	p.emitCompleted(dismissed, objects)

	// Cleanup: remove from manager and unexport
	if p.manager != nil {
		p.manager.RemovePrompt(p.path)
	}
}

// emitCompleted emits the Completed signal
func (p *Prompt) emitCompleted(dismissed bool, result interface{}) {
	var resultVariant dbus.Variant
	if result == nil {
		resultVariant = dbus.MakeVariant([]dbus.ObjectPath{})
	} else {
		resultVariant = dbus.MakeVariant(result)
	}

	signal := &dbus.Signal{
		Path: p.path,
		Name: PromptInterface + ".Completed",
		Body: []interface{}{dismissed, resultVariant},
	}

	p.conn.Emit(signal.Path, signal.Name, signal.Body...)
}
