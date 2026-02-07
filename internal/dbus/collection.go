package dbus

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	return exportDBusObject(cm.conn, coll, coll.path, CollectionInterface, CollectionIntrospectXML, true)
}

// Path returns the collection's object path
func (c *Collection) Path() dbus.ObjectPath {
	return c.path
}

// lastSyncUnix returns the last sync time from Bitwarden status as a Unix timestamp.
// Returns 0 if the status call fails or lastSync is empty.
// Note: Status() uses doRequest which already checks HTTP status codes >= 400, so
// we don't need to check status.Success here - an API error would have been returned
// as an HTTP error.
func (c *Collection) lastSyncUnix(ctx context.Context) int64 {
	status, err := c.bwClient.Status(ctx)
	if err != nil {
		return 0
	}
	lastSync := status.Data.Template.LastSync
	if lastSync == nil || *lastSync == "" {
		return 0
	}
	// Try RFC3339Nano first (Bitwarden format), then RFC3339
	t, err := time.Parse(time.RFC3339Nano, *lastSync)
	if err != nil {
		t, err = time.Parse(time.RFC3339, *lastSync)
		if err != nil {
			return 0
		}
	}
	u := t.Unix()
	if u < 0 {
		return 0
	}
	return u
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
	return NoPrompt, toDBusError(fmt.Errorf("cannot delete default collection"))
}

// SearchItems searches for items matching the given attributes (D-Bus method)
func (c *Collection) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	results, err := searchAndFilterItems(ctx, c.bwClient, c.itemManager, c, attributes)
	if err != nil {
		return nil, toDBusError(err)
	}

	return results, nil
}

// CreateItem creates a new item in the collection (D-Bus method)
func (c *Collection) CreateItem(properties map[string]dbus.Variant, secret Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	// Decrypt the secret if using encrypted session
	session, dbusErr := c.sessionManager.GetSessionOrError(secret.Session)
	if dbusErr != nil {
		return NoPrompt, NoPrompt, dbusErr
	}

	decryptedValue, err := session.DecryptSecret(secret.Value, secret.Parameters)
	if err != nil {
		return NoPrompt, NoPrompt, toDBusError(fmt.Errorf("failed to decrypt secret: %w", err))
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
		var items []bitwarden.Item
		var err error
		if uri != "" {
			items, err = c.bwClient.SearchItems(ctx, uri)
		} else {
			items, err = c.bwClient.ListItems(ctx)
		}
		if err != nil {
			// If we can't fetch candidate items, we can't safely replace - fail the operation
			return NoPrompt, NoPrompt, toDBusError(
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
					return NoPrompt, NoPrompt, toDBusError(err)
				}

				dbusItem, err := c.itemManager.GetOrCreateItem(updated, c)
				if err != nil {
					return NoPrompt, NoPrompt, toDBusError(err)
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
		return NoPrompt, NoPrompt, toDBusError(err)
	}

	dbusItem, err := c.itemManager.GetOrCreateItem(created, c)
	if err != nil {
		return NoPrompt, NoPrompt, toDBusError(err)
	}

	// Emit ItemCreated signal for new item
	EmitItemCreated(c.conn, c.path, dbusItem.Path())

	return dbusItem.Path(), NoPrompt, nil
}

// Get implements org.freedesktop.DBus.Properties.Get
func (c *Collection) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != CollectionInterface {
		return dbus.Variant{}, toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	// Handle timestamp properties outside the lock — they only need bwClient (immutable).
	switch property {
	case "Created", "Modified":
		return dbus.MakeVariant(uint64(c.lastSyncUnix(context.Background()))), nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	switch property {
	case "Items":
		// Return all item paths, ensuring each item is exported
		ctx := context.Background()
		paths, err := getLoginItemPaths(ctx, c.bwClient, c.itemManager, c)
		if err != nil {
			return dbus.Variant{}, toDBusError(err)
		}
		return dbus.MakeVariant(paths), nil

	case "Label":
		return dbus.MakeVariant(c.label), nil

	case "Locked":
		ctx := context.Background()
		return dbus.MakeVariant(c.bwClient.IsLockedSafe(ctx)), nil

	default:
		return dbus.Variant{}, toDBusError(fmt.Errorf("unknown property: %s", property))
	}
}

// Set implements org.freedesktop.DBus.Properties.Set
func (c *Collection) Set(iface, property string, value dbus.Variant) *dbus.Error {
	if iface != CollectionInterface {
		return toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch property {
	case "Label":
		label, ok := value.Value().(string)
		if !ok {
			return toDBusError(fmt.Errorf("invalid label type"))
		}
		c.label = label
		return nil

	default:
		return toDBusError(fmt.Errorf("unknown or read-only property: %s", property))
	}
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll
func (c *Collection) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != CollectionInterface {
		return nil, toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	// Fetch timestamp outside the lock — it only needs bwClient (immutable).
	ts := uint64(c.lastSyncUnix(context.Background()))

	c.mu.RLock()
	defer c.mu.RUnlock()

	ctx := context.Background()

	locked := c.bwClient.IsLockedSafe(ctx)

	// Get item paths, using empty list on error
	paths, err := getLoginItemPaths(ctx, c.bwClient, c.itemManager, c)
	if err != nil {
		paths = nil
	}

	props := map[string]dbus.Variant{
		"Items":    dbus.MakeVariant(paths),
		"Label":    dbus.MakeVariant(c.label),
		"Locked":   dbus.MakeVariant(locked),
		"Created":  dbus.MakeVariant(ts),
		"Modified": dbus.MakeVariant(ts),
	}

	return props, nil
}
