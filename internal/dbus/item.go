package dbus

import (
	"context"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/mapping"
)

// Item represents a secret item exposed via D-Bus
type Item struct {
	conn           *dbus.Conn
	path           dbus.ObjectPath
	bwItem         *bitwarden.Item
	bwClient       *bitwarden.Client
	sessionManager *SessionManager
	collection     *Collection
	itemManager    *ItemManager
	mu             sync.RWMutex
}

// itemEntry represents an item in the process of being exported or already exported
type itemEntry struct {
	item  *Item
	ready chan struct{}
	err   error
}

// ItemManager manages item objects
type ItemManager struct {
	conn           *dbus.Conn
	bwClient       *bitwarden.Client
	sessionManager *SessionManager
	items          map[dbus.ObjectPath]*itemEntry
	mu             sync.RWMutex
	exportFunc     func(*Item) error // for testing; defaults to exportItem
}

// NewItemManager creates a new item manager
func NewItemManager(conn *dbus.Conn, bwClient *bitwarden.Client, sessionManager *SessionManager) *ItemManager {
	return &ItemManager{
		conn:           conn,
		bwClient:       bwClient,
		sessionManager: sessionManager,
		items:          make(map[dbus.ObjectPath]*itemEntry),
	}
}

// GetOrCreateItem gets or creates an Item for a Bitwarden item
func (im *ItemManager) GetOrCreateItem(bwItem *bitwarden.Item, collection *Collection) (*Item, error) {
	path := ItemPathFromID(bwItem.ID)

	// Fast path: check if entry exists
	im.mu.RLock()
	entry, exists := im.items[path]
	im.mu.RUnlock()

	if exists {
		// Wait for ready (export to complete or fail)
		<-entry.ready

		// Check if export failed
		if entry.err != nil {
			return nil, entry.err
		}

		// Update the backing item under item's lock (not manager's lock)
		entry.item.mu.Lock()
		entry.item.bwItem = bwItem
		entry.item.mu.Unlock()
		return entry.item, nil
	}

	// Create path: insert placeholder, unlock, export, signal ready
	entry = &itemEntry{
		ready: make(chan struct{}),
	}

	im.mu.Lock()
	// Double-check: another goroutine might have created it
	if existing, ok := im.items[path]; ok {
		im.mu.Unlock()
		// Wait for the other goroutine's export
		<-existing.ready
		if existing.err != nil {
			return nil, existing.err
		}
		// Update the backing item
		existing.item.mu.Lock()
		existing.item.bwItem = bwItem
		existing.item.mu.Unlock()
		return existing.item, nil
	}

	// We won the race, insert placeholder
	im.items[path] = entry
	im.mu.Unlock()

	// Now export without holding the lock
	item := &Item{
		conn:           im.conn,
		path:           path,
		bwItem:         bwItem,
		bwClient:       im.bwClient,
		sessionManager: im.sessionManager,
		collection:     collection,
		itemManager:    im,
	}

	// Use injected export function if set (for testing), else use real export
	exportFn := im.exportFunc
	if exportFn == nil {
		exportFn = im.exportItem
	}

	err := exportFn(item)
	if err != nil {
		// Export failed: set error, close ready, delete entry
		entry.err = err
		close(entry.ready)

		im.mu.Lock()
		delete(im.items, path)
		im.mu.Unlock()

		return nil, err
	}

	// Success: set item, close ready
	entry.item = item
	close(entry.ready)

	return item, nil
}

// GetItem retrieves an item by path
func (im *ItemManager) GetItem(path dbus.ObjectPath) (*Item, bool) {
	im.mu.RLock()
	entry, ok := im.items[path]
	im.mu.RUnlock()

	if !ok {
		return nil, false
	}

	// Wait for ready
	<-entry.ready

	// Check if export failed
	if entry.err != nil {
		return nil, false
	}

	return entry.item, true
}

// RemoveItem removes an item and unexports all its D-Bus interfaces
func (im *ItemManager) RemoveItem(path dbus.ObjectPath) {
	// First, get the entry outside the lock
	im.mu.RLock()
	entry, ok := im.items[path]
	im.mu.RUnlock()

	if !ok {
		return
	}

	// Wait for export to complete (or fail)
	<-entry.ready

	// Now delete and unexport
	im.mu.Lock()
	delete(im.items, path)
	im.mu.Unlock()

	// Unexport all interfaces that were exported (only if export succeeded and conn exists)
	if entry.err == nil && im.conn != nil {
		im.conn.Export(nil, path, ItemInterface)
		im.conn.Export(nil, path, PropertiesInterface)
		im.conn.Export(nil, path, "org.freedesktop.DBus.Introspectable")
	}
}

// exportItem exports an item to D-Bus
func (im *ItemManager) exportItem(item *Item) error {
	if err := im.conn.Export(item, item.path, ItemInterface); err != nil {
		return err
	}

	if err := im.conn.Export(item, item.path, PropertiesInterface); err != nil {
		return err
	}

	if err := im.conn.Export(introspectable(ItemIntrospectXML), item.path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}

	return nil
}

// ItemPathFromID creates an item path from a Bitwarden item ID
func ItemPathFromID(id string) dbus.ObjectPath {
	return dbus.ObjectPath(CollectionPath + "default/" + SanitizeID(id))
}

// Path returns the item's object path
func (i *Item) Path() dbus.ObjectPath {
	return i.path
}

// ID returns the Bitwarden item ID
func (i *Item) ID() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.bwItem.ID
}

// Delete deletes the item (D-Bus method)
func (i *Item) Delete() (dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	i.mu.RLock()
	id := i.bwItem.ID
	collPath := i.collection.path
	i.mu.RUnlock()

	if err := i.bwClient.DeleteItem(ctx, id); err != nil {
		return NoPrompt, toDBusError(err)
	}

	// Remove from manager and unexport all interfaces
	i.itemManager.RemoveItem(i.path)

	// Emit ItemDeleted signal using actual collection path
	EmitItemDeleted(i.conn, collPath, i.path)

	return NoPrompt, nil
}

// GetSecret returns the item's secret (D-Bus method)
func (i *Item) GetSecret(sessionPath dbus.ObjectPath) (Secret, *dbus.Error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.bwItem.Login == nil || i.bwItem.Login.Password == nil {
		return Secret{}, toDBusError(fmt.Errorf("item has no password"))
	}

	// Get session for encryption
	session, ok := i.sessionManager.GetSession(sessionPath)
	if !ok {
		return Secret{}, &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}

	plaintext := []byte(*i.bwItem.Login.Password)

	// Encrypt if needed
	value, params, err := session.EncryptSecret(plaintext)
	if err != nil {
		return Secret{}, toDBusError(err)
	}

	secret := Secret{
		Session:     sessionPath,
		Parameters:  params,
		Value:       value,
		ContentType: "text/plain",
	}

	return secret, nil
}

// SetSecret sets the item's secret (D-Bus method)
func (i *Item) SetSecret(secret Secret) *dbus.Error {
	ctx := context.Background()

	// Decrypt the secret if using encrypted session
	session, ok := i.sessionManager.GetSession(secret.Session)
	if !ok {
		return &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}

	decryptedValue, err := session.DecryptSecret(secret.Value, secret.Parameters)
	if err != nil {
		return toDBusError(fmt.Errorf("failed to decrypt secret: %w", err))
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// Guard against nil Login struct
	if i.bwItem.Login == nil {
		return toDBusError(fmt.Errorf("item has no login credentials"))
	}

	password := string(decryptedValue)
	i.bwItem.Login.Password = &password

	// Use ToUpdateRequest to preserve all fields
	req := i.bwItem.ToUpdateRequest()

	updated, err := i.bwClient.UpdateItem(ctx, i.bwItem.ID, req)
	if err != nil {
		return toDBusError(err)
	}

	i.bwItem = updated

	// Emit ItemChanged signal using actual collection path
	EmitItemChanged(i.conn, i.collection.path, i.path)

	return nil
}

// Get implements org.freedesktop.DBus.Properties.Get
func (i *Item) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != ItemInterface {
		return dbus.Variant{}, toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	// Handle Locked property separately since it needs to query bwClient
	// without holding the lock
	if property == "Locked" {
		ctx := context.Background()
		locked, err := i.bwClient.IsLocked(ctx)
		if err != nil {
			// Default to locked=true on error (safe default)
			locked = true
		}
		return dbus.MakeVariant(locked), nil
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	switch property {
	case "Attributes":
		attrs := mapping.ItemToAttributes(i.bwItem)
		return dbus.MakeVariant(attrs), nil

	case "Label":
		return dbus.MakeVariant(i.bwItem.Name), nil

	case "Created":
		return dbus.MakeVariant(uint64(i.bwItem.CreationDate.Unix())), nil

	case "Modified":
		return dbus.MakeVariant(uint64(i.bwItem.RevisionDate.Unix())), nil

	default:
		return dbus.Variant{}, toDBusError(fmt.Errorf("unknown property: %s", property))
	}
}

// Set implements org.freedesktop.DBus.Properties.Set
func (i *Item) Set(iface, property string, value dbus.Variant) *dbus.Error {
	if iface != ItemInterface {
		return toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	ctx := context.Background()

	i.mu.Lock()
	defer i.mu.Unlock()

	switch property {
	case "Label":
		label, ok := value.Value().(string)
		if !ok {
			return toDBusError(fmt.Errorf("invalid label type"))
		}
		i.bwItem.Name = label

		// Use ToUpdateRequest to preserve all fields
		req := i.bwItem.ToUpdateRequest()

		updated, err := i.bwClient.UpdateItem(ctx, i.bwItem.ID, req)
		if err != nil {
			return toDBusError(err)
		}
		i.bwItem = updated

		// Emit ItemChanged signal using actual collection path
		EmitItemChanged(i.conn, i.collection.path, i.path)

		return nil

	case "Attributes":
		attrs, ok := value.Value().(map[string]string)
		if !ok {
			return toDBusError(fmt.Errorf("invalid attributes type: expected map[string]string"))
		}

		// Update item from attributes
		mapping.UpdateItemFromAttributes(i.bwItem, attrs)

		// Use ToUpdateRequest to preserve all fields
		req := i.bwItem.ToUpdateRequest()

		// Save to Bitwarden
		updated, err := i.bwClient.UpdateItem(ctx, i.bwItem.ID, req)
		if err != nil {
			return toDBusError(fmt.Errorf("failed to update item: %w", err))
		}
		i.bwItem = updated

		// Emit ItemChanged signal using actual collection path
		EmitItemChanged(i.conn, i.collection.path, i.path)

		return nil

	default:
		return toDBusError(fmt.Errorf("unknown or read-only property: %s", property))
	}
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll
func (i *Item) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != ItemInterface {
		return nil, toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	// Check lock state before holding the lock
	ctx := context.Background()
	locked, err := i.bwClient.IsLocked(ctx)
	if err != nil {
		// Default to locked=true on error (safe default)
		locked = true
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	props := map[string]dbus.Variant{
		"Locked":     dbus.MakeVariant(locked),
		"Attributes": dbus.MakeVariant(mapping.ItemToAttributes(i.bwItem)),
		"Label":      dbus.MakeVariant(i.bwItem.Name),
		"Created":    dbus.MakeVariant(uint64(i.bwItem.CreationDate.Unix())),
		"Modified":   dbus.MakeVariant(uint64(i.bwItem.RevisionDate.Unix())),
	}

	return props, nil
}
