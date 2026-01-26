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

// RemoveItem removes an item
func (im *ItemManager) RemoveItem(path dbus.ObjectPath) {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, ok := im.items[path]; ok {
		im.conn.Export(nil, path, ItemInterface)
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
	i.mu.RUnlock()

	if err := i.bwClient.DeleteItem(ctx, id); err != nil {
		return NoPrompt, dbus.MakeFailedError(err)
	}

	return NoPrompt, nil
}

// GetSecret returns the item's secret (D-Bus method)
func (i *Item) GetSecret(sessionPath dbus.ObjectPath) (Secret, *dbus.Error) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.bwItem.Login == nil || i.bwItem.Login.Password == nil {
		return Secret{}, dbus.MakeFailedError(fmt.Errorf("item has no password"))
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
		return Secret{}, dbus.MakeFailedError(err)
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
		return dbus.MakeFailedError(fmt.Errorf("failed to decrypt secret: %w", err))
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	password := string(decryptedValue)
	i.bwItem.Login.Password = &password

	// Update in Bitwarden
	req := bitwarden.CreateItemRequest{
		Type:     bitwarden.ItemTypeLogin,
		Name:     i.bwItem.Name,
		FolderID: i.bwItem.FolderID,
		Login:    i.bwItem.Login,
		Fields:   i.bwItem.Fields,
	}

	updated, err := i.bwClient.UpdateItem(ctx, i.bwItem.ID, req)
	if err != nil {
		return dbus.MakeFailedError(err)
	}

	i.bwItem = updated
	return nil
}

// Get implements org.freedesktop.DBus.Properties.Get
func (i *Item) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != ItemInterface {
		return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	switch property {
	case "Locked":
		// Items are unlocked if we can access them
		return dbus.MakeVariant(false), nil

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
		return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown property: %s", property))
	}
}

// Set implements org.freedesktop.DBus.Properties.Set
func (i *Item) Set(iface, property string, value dbus.Variant) *dbus.Error {
	if iface != ItemInterface {
		return dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
	}

	ctx := context.Background()

	i.mu.Lock()
	defer i.mu.Unlock()

	switch property {
	case "Label":
		label, ok := value.Value().(string)
		if !ok {
			return dbus.MakeFailedError(fmt.Errorf("invalid label type"))
		}
		i.bwItem.Name = label

		// Update in Bitwarden
		req := bitwarden.CreateItemRequest{
			Type:     bitwarden.ItemTypeLogin,
			Name:     label,
			FolderID: i.bwItem.FolderID,
			Login:    i.bwItem.Login,
			Fields:   i.bwItem.Fields,
		}

		updated, err := i.bwClient.UpdateItem(ctx, i.bwItem.ID, req)
		if err != nil {
			return dbus.MakeFailedError(err)
		}
		i.bwItem = updated
		return nil

	case "Attributes":
		// Attributes are derived from Bitwarden fields, not directly settable
		return dbus.MakeFailedError(fmt.Errorf("attributes are read-only"))

	default:
		return dbus.MakeFailedError(fmt.Errorf("unknown or read-only property: %s", property))
	}
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll
func (i *Item) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != ItemInterface {
		return nil, dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	props := map[string]dbus.Variant{
		"Locked":     dbus.MakeVariant(false),
		"Attributes": dbus.MakeVariant(mapping.ItemToAttributes(i.bwItem)),
		"Label":      dbus.MakeVariant(i.bwItem.Name),
		"Created":    dbus.MakeVariant(uint64(i.bwItem.CreationDate.Unix())),
		"Modified":   dbus.MakeVariant(uint64(i.bwItem.RevisionDate.Unix())),
	}

	return props, nil
}
