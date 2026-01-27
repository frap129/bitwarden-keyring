package dbus

import (
	"context"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/mapping"
)

// Collection represents a secret collection exposed via D-Bus
type Collection struct {
	conn           *dbus.Conn
	path           dbus.ObjectPath
	name           string
	label          string
	bwClient       *bitwarden.Client
	itemManager    *ItemManager
	sessionManager *SessionManager
	mu             sync.RWMutex
}

// CollectionManager manages collection objects
type CollectionManager struct {
	conn           *dbus.Conn
	bwClient       *bitwarden.Client
	itemManager    *ItemManager
	sessionManager *SessionManager
	collections    map[dbus.ObjectPath]*Collection
	defaultAlias   dbus.ObjectPath
	mu             sync.RWMutex
}

// NewCollectionManager creates a new collection manager
func NewCollectionManager(conn *dbus.Conn, bwClient *bitwarden.Client, itemManager *ItemManager, sessionManager *SessionManager) *CollectionManager {
	return &CollectionManager{
		conn:           conn,
		bwClient:       bwClient,
		itemManager:    itemManager,
		sessionManager: sessionManager,
		collections:    make(map[dbus.ObjectPath]*Collection),
		defaultAlias:   DefaultCollectionPath,
	}
}

// EnsureDefaultCollection ensures the default collection exists
func (cm *CollectionManager) EnsureDefaultCollection() (*Collection, error) {
	path := DefaultCollectionPath

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if coll, ok := cm.collections[path]; ok {
		return coll, nil
	}

	coll := &Collection{
		conn:           cm.conn,
		path:           path,
		name:           "default",
		label:          "Default",
		bwClient:       cm.bwClient,
		itemManager:    cm.itemManager,
		sessionManager: cm.sessionManager,
	}

	if err := cm.exportCollection(coll); err != nil {
		return nil, err
	}

	cm.collections[path] = coll
	return coll, nil
}

// GetCollection retrieves a collection by path
func (cm *CollectionManager) GetCollection(path dbus.ObjectPath) (*Collection, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	coll, ok := cm.collections[path]
	return coll, ok
}

// GetCollectionPaths returns all collection paths
func (cm *CollectionManager) GetCollectionPaths() []dbus.ObjectPath {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	paths := make([]dbus.ObjectPath, 0, len(cm.collections))
	for path := range cm.collections {
		paths = append(paths, path)
	}
	return paths
}

// GetDefaultAlias returns the default collection path
func (cm *CollectionManager) GetDefaultAlias() dbus.ObjectPath {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.defaultAlias
}

// exportCollection exports a collection to D-Bus
func (cm *CollectionManager) exportCollection(coll *Collection) error {
	if err := cm.conn.Export(coll, coll.path, CollectionInterface); err != nil {
		return err
	}

	if err := cm.conn.Export(coll, coll.path, PropertiesInterface); err != nil {
		return err
	}

	if err := cm.conn.Export(introspectable(CollectionIntrospectXML), coll.path, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}

	return nil
}

// Path returns the collection's object path
func (c *Collection) Path() dbus.ObjectPath {
	return c.path
}

// hasMeaningfulAttrs checks if attrs has at least one identity attribute.
// This prevents accidental replacement when attrs is empty or only has schema.
func hasMeaningfulAttrs(attrs map[string]string) bool {
	identityKeys := []string{
		"label", "service", "domain", "server", "username", "user",
		mapping.AttrService, mapping.AttrUsername, mapping.AttrDomain,
		mapping.AttrServer,
	}
	for _, key := range identityKeys {
		if v, ok := attrs[key]; ok && v != "" {
			return true
		}
	}
	return false
}

// Delete deletes the collection (D-Bus method)
func (c *Collection) Delete() (dbus.ObjectPath, *dbus.Error) {
	// We don't support deleting the default collection
	return NoPrompt, dbus.MakeFailedError(fmt.Errorf("cannot delete default collection"))
}

// SearchItems searches for items matching the given attributes (D-Bus method)
func (c *Collection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	// Build search parameters from attributes
	uri := mapping.BuildURIFromAttributes(attributes)

	var items []bitwarden.Item
	var err error

	if uri != "" {
		items, err = c.bwClient.SearchItems(ctx, uri)
	} else {
		items, err = c.bwClient.ListItems(ctx)
	}

	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	// Filter by attributes
	var results []dbus.ObjectPath
	for _, item := range items {
		if mapping.MatchesAttributes(&item, attributes) {
			itemCopy := item
			dbusItem, err := c.itemManager.GetOrCreateItem(&itemCopy, c)
			if err != nil {
				continue
			}
			results = append(results, dbusItem.Path())
		}
	}

	return results, nil
}

// CreateItem creates a new item in the collection (D-Bus method)
func (c *Collection) CreateItem(properties map[string]dbus.Variant, secret Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	// Decrypt the secret if using encrypted session
	session, ok := c.sessionManager.GetSession(secret.Session)
	if !ok {
		return NoPrompt, NoPrompt, &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}

	decryptedValue, err := session.DecryptSecret(secret.Value, secret.Parameters)
	if err != nil {
		return NoPrompt, NoPrompt, dbus.MakeFailedError(fmt.Errorf("failed to decrypt secret: %w", err))
	}

	// Extract label from properties
	label := "Unnamed"
	if labelVar, ok := properties[PropItemLabel]; ok {
		if l, ok := labelVar.Value().(string); ok {
			label = l
		}
	}

	// Extract attributes from properties
	var attrs map[string]string
	if attrsVar, ok := properties[PropItemAttributes]; ok {
		if a, ok := attrsVar.Value().(map[string]string); ok {
			attrs = a
		}
	}

	// Build URI from attributes
	uri := mapping.BuildURIFromAttributes(attrs)
	username := mapping.GetUsername(attrs)

	// If replace is true, try to find and update existing item
	// Only replace if attrs contains meaningful identity attributes
	if replace && attrs != nil && hasMeaningfulAttrs(attrs) {
		items, err := c.bwClient.ListItems(ctx)
		if err != nil {
			// If we can't list items, we can't safely replace - fail the operation
			return NoPrompt, NoPrompt, dbus.MakeFailedError(
				fmt.Errorf("cannot check for existing items: %w", err))
		}
		for _, item := range items {
			if mapping.MatchesAttributes(&item, attrs) {
				// Update existing item with all attributes first
				mapping.UpdateItemFromAttributes(&item, attrs)

				// Then set password and label
				password := string(decryptedValue)
				item.Login.Password = &password
				item.Name = label

				// Use ToUpdateRequest to preserve all fields
				req := item.ToUpdateRequest()

				updated, err := c.bwClient.UpdateItem(ctx, item.ID, req)
				if err != nil {
					return NoPrompt, NoPrompt, dbus.MakeFailedError(err)
				}

				dbusItem, err := c.itemManager.GetOrCreateItem(updated, c)
				if err != nil {
					return NoPrompt, NoPrompt, dbus.MakeFailedError(err)
				}

				// Emit ItemChanged signal for updated item
				EmitItemChanged(c.conn, c.path, dbusItem.Path())

				return dbusItem.Path(), NoPrompt, nil
			}
		}
	}

	// Create new item
	password := string(decryptedValue)
	login := &bitwarden.Login{
		Password: &password,
	}

	if username != "" {
		login.Username = &username
	}

	if uri != "" {
		login.URIs = []bitwarden.URI{{URI: uri}}
	}

	req := bitwarden.CreateItemRequest{
		Type:  bitwarden.ItemTypeLogin,
		Name:  label,
		Login: login,
	}

	created, err := c.bwClient.CreateItem(ctx, req)
	if err != nil {
		return NoPrompt, NoPrompt, dbus.MakeFailedError(err)
	}

	dbusItem, err := c.itemManager.GetOrCreateItem(created, c)
	if err != nil {
		return NoPrompt, NoPrompt, dbus.MakeFailedError(err)
	}

	// Emit ItemCreated signal for new item
	EmitItemCreated(c.conn, c.path, dbusItem.Path())

	return dbusItem.Path(), NoPrompt, nil
}

// Get implements org.freedesktop.DBus.Properties.Get
func (c *Collection) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != CollectionInterface {
		return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	switch property {
	case "Items":
		// Return all item paths, ensuring each item is exported
		ctx := context.Background()
		items, err := c.bwClient.ListItems(ctx)
		if err != nil {
			return dbus.Variant{}, dbus.MakeFailedError(err)
		}

		paths := make([]dbus.ObjectPath, 0, len(items))
		for _, item := range items {
			if item.Type == bitwarden.ItemTypeLogin {
				// Ensure item is exported before returning its path
				itemCopy := item
				dbusItem, err := c.itemManager.GetOrCreateItem(&itemCopy, c)
				if err != nil {
					continue // Skip items that can't be exported
				}
				paths = append(paths, dbusItem.Path())
			}
		}
		return dbus.MakeVariant(paths), nil

	case "Label":
		return dbus.MakeVariant(c.label), nil

	case "Locked":
		ctx := context.Background()
		// Default to locked=true on error (safe default)
		locked, err := c.bwClient.IsLocked(ctx)
		if err != nil {
			locked = true
		}
		return dbus.MakeVariant(locked), nil

	case "Created":
		return dbus.MakeVariant(uint64(0)), nil

	case "Modified":
		return dbus.MakeVariant(uint64(0)), nil

	default:
		return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown property: %s", property))
	}
}

// Set implements org.freedesktop.DBus.Properties.Set
func (c *Collection) Set(iface, property string, value dbus.Variant) *dbus.Error {
	if iface != CollectionInterface {
		return dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch property {
	case "Label":
		label, ok := value.Value().(string)
		if !ok {
			return dbus.MakeFailedError(fmt.Errorf("invalid label type"))
		}
		c.label = label
		return nil

	default:
		return dbus.MakeFailedError(fmt.Errorf("unknown or read-only property: %s", property))
	}
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll
func (c *Collection) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != CollectionInterface {
		return nil, dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	ctx := context.Background()

	// Default to locked=true on error (safe default)
	locked, err := c.bwClient.IsLocked(ctx)
	if err != nil {
		locked = true
	}

	// Return empty items list on error
	items, err := c.bwClient.ListItems(ctx)
	if err != nil {
		items = nil
	}
	paths := make([]dbus.ObjectPath, 0, len(items))
	for _, item := range items {
		if item.Type == bitwarden.ItemTypeLogin {
			// Ensure item is exported before returning its path
			itemCopy := item
			dbusItem, err := c.itemManager.GetOrCreateItem(&itemCopy, c)
			if err != nil {
				continue // Skip items that can't be exported
			}
			paths = append(paths, dbusItem.Path())
		}
	}

	props := map[string]dbus.Variant{
		"Items":    dbus.MakeVariant(paths),
		"Label":    dbus.MakeVariant(c.label),
		"Locked":   dbus.MakeVariant(locked),
		"Created":  dbus.MakeVariant(uint64(0)),
		"Modified": dbus.MakeVariant(uint64(0)),
	}

	return props, nil
}
