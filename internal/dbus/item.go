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

// ItemManager manages item objects
type ItemManager struct {
	conn           *dbus.Conn
	bwClient       *bitwarden.Client
	sessionManager *SessionManager
	items          map[dbus.ObjectPath]*Item
	mu             sync.RWMutex
}

// NewItemManager creates a new item manager
func NewItemManager(conn *dbus.Conn, bwClient *bitwarden.Client, sessionManager *SessionManager) *ItemManager {
	return &ItemManager{
		conn:           conn,
		bwClient:       bwClient,
		sessionManager: sessionManager,
		items:          make(map[dbus.ObjectPath]*Item),
	}
}

// GetOrCreateItem gets or creates an Item for a Bitwarden item
func (im *ItemManager) GetOrCreateItem(bwItem *bitwarden.Item, collection *Collection) (*Item, error) {
	path := ItemPathFromID(bwItem.ID)

	im.mu.Lock()
	defer im.mu.Unlock()

	if item, ok := im.items[path]; ok {
		// Update the backing item
		item.mu.Lock()
		item.bwItem = bwItem
		item.mu.Unlock()
		return item, nil
	}

	item := &Item{
		conn:           im.conn,
		path:           path,
		bwItem:         bwItem,
		bwClient:       im.bwClient,
		sessionManager: im.sessionManager,
		collection:     collection,
		itemManager:    im,
	}

	if err := im.exportItem(item); err != nil {
		return nil, err
	}

	im.items[path] = item
	return item, nil
}

// GetItem retrieves an item by path
func (im *ItemManager) GetItem(path dbus.ObjectPath) (*Item, bool) {
	im.mu.RLock()
	defer im.mu.RUnlock()
	item, ok := im.items[path]
	return item, ok
}

// RemoveItem removes an item and unexports all its D-Bus interfaces
func (im *ItemManager) RemoveItem(path dbus.ObjectPath) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, ok := im.items[path]; ok {
		// Unexport all interfaces that were exported
		im.conn.Export(nil, path, ItemInterface)
		im.conn.Export(nil, path, PropertiesInterface)
		im.conn.Export(nil, path, "org.freedesktop.DBus.Introspectable")
		delete(im.items, path)
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
