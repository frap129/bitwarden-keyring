package dbus

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// Prompt represents an unlock prompt
type Prompt struct {
	conn     *dbus.Conn
	path     dbus.ObjectPath
	bwClient *bitwarden.Client
	objects  []dbus.ObjectPath
	done     bool
	mu       sync.Mutex
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
	if err := pm.conn.Export(prompt, prompt.path, PromptInterface); err != nil {
		return err
	}

	if err := pm.conn.Export(introspectable(PromptIntrospectXML), prompt.path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}

	return nil
}

// RemovePrompt removes a prompt
func (pm *PromptManager) RemovePrompt(path dbus.ObjectPath) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, ok := pm.prompts[path]; ok {
		pm.conn.Export(nil, path, PromptInterface)
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
	defer p.mu.Unlock()

	if p.done {
		return nil
	}

	// Try to unlock the vault
	go p.doUnlock()

	return nil
}

// Dismiss dismisses the prompt (D-Bus method)
func (p *Prompt) Dismiss() *dbus.Error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return nil
	}

	p.done = true

	// Emit Completed signal with dismissed=true
	p.emitCompleted(true, nil)

	return nil
}

// doUnlock performs the actual unlock operation
func (p *Prompt) doUnlock() {
	ctx := context.Background()

	// Prompt for password
	password, err := p.bwClient.SessionManager().PromptForPassword()
	if err != nil {
		p.emitCompleted(true, nil)
		return
	}

	// Unlock the vault
	_, err = p.bwClient.Unlock(ctx, password)
	if err != nil {
		p.emitCompleted(true, nil)
		return
	}

	p.mu.Lock()
	p.done = true
	objects := p.objects
	p.mu.Unlock()

	// Emit Completed signal with the unlocked objects
	p.emitCompleted(false, objects)
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
