package dbus

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/mapping"
)

// toDBusError converts backend errors to D-Bus errors with safe messages.
// It maps specific errors to their D-Bus equivalents and redacts generic errors
// to prevent information leakage.
func toDBusError(err error) *dbus.Error {
	if err == nil {
		return nil
	}

	// Map ErrVaultLocked to IsLocked error
	if errors.Is(err, bitwarden.ErrVaultLocked) {
		return &dbus.Error{
			Name: ErrIsLocked,
			Body: []interface{}{"Vault is locked"},
		}
	}

	// Map ErrUserCancelled to PromptDismissed error
	if errors.Is(err, bitwarden.ErrUserCancelled) {
		return &dbus.Error{
			Name: "org.freedesktop.Secret.Error.PromptDismissed",
			Body: []interface{}{"Prompt was dismissed"},
		}
	}

	// For all other errors (including APIError), return a generic "backend error"
	// This prevents leaking HTTP bodies or other sensitive information
	return &dbus.Error{
		Name: "org.freedesktop.Secret.Error.Failed",
		Body: []interface{}{"backend error"},
	}
}

// Service implements the org.freedesktop.Secret.Service interface
type Service struct {
	conn              *dbus.Conn
	bwClient          *bitwarden.Client
	sessionManager    *SessionManager
	collectionManager *CollectionManager
	itemManager       *ItemManager
	promptManager     *PromptManager
	mu                sync.RWMutex
}

// NewService creates a new Secret Service
func NewService(conn *dbus.Conn, bwClient *bitwarden.Client) (*Service, error) {
	sessionManager := NewSessionManager(conn)
	itemManager := NewItemManager(conn, bwClient, sessionManager)
	collectionManager := NewCollectionManager(conn, bwClient, itemManager, sessionManager)
	promptManager := NewPromptManager(conn, bwClient)

	svc := &Service{
		conn:              conn,
		bwClient:          bwClient,
		sessionManager:    sessionManager,
		collectionManager: collectionManager,
		itemManager:       itemManager,
		promptManager:     promptManager,
	}

	// Ensure default collection exists
	if _, err := collectionManager.EnsureDefaultCollection(); err != nil {
		return nil, err
	}

	return svc, nil
}

// Export exports the service to D-Bus
func (s *Service) Export() error {
	// Export the service interface
	if err := s.conn.Export(s, ServicePath, ServiceInterface); err != nil {
		return fmt.Errorf("failed to export service: %w", err)
	}

	// Export properties interface
	if err := s.conn.Export(s, ServicePath, PropertiesInterface); err != nil {
		return fmt.Errorf("failed to export properties: %w", err)
	}

	// Export introspection
	if err := s.conn.Export(introspectable(ServiceIntrospectXML), ServicePath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return fmt.Errorf("failed to export introspection: %w", err)
	}

	// Export alias path for default collection
	// This allows clients to access /org/freedesktop/secrets/aliases/default directly
	aliasDefaultPath := dbus.ObjectPath(AliasPath + "default")
	coll, _ := s.collectionManager.GetCollection(DefaultCollectionPath)
	if coll != nil {
		if err := s.conn.Export(coll, aliasDefaultPath, CollectionInterface); err != nil {
			return fmt.Errorf("failed to export collection at alias path: %w", err)
		}
		if err := s.conn.Export(coll, aliasDefaultPath, PropertiesInterface); err != nil {
			return fmt.Errorf("failed to export properties at alias path: %w", err)
		}
		if err := s.conn.Export(introspectable(CollectionIntrospectXML), aliasDefaultPath, "org.freedesktop.DBus.Introspectable"); err != nil {
			return fmt.Errorf("failed to export introspection at alias path: %w", err)
		}
	}

	// Request the bus name
	reply, err := s.conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("failed to request bus name: %w", err)
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("bus name %s already taken", BusName)
	}

	return nil
}

// OpenSession opens a new session (D-Bus method)
func (s *Service) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	// Extract input bytes (client's DH public key for encrypted sessions)
	var inputBytes []byte
	if input.Value() != nil {
		switch v := input.Value().(type) {
		case []byte:
			inputBytes = v
		case string:
			inputBytes = []byte(v)
		}
	}

	session, output, err := s.sessionManager.CreateSession(algorithm, inputBytes)
	if err != nil {
		return dbus.Variant{}, NoPrompt, toDBusError(err)
	}

	return output, session.Path(), nil
}

// CreateCollection creates a new collection (D-Bus method)
func (s *Service) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	// We only support the default collection for now
	coll, err := s.collectionManager.EnsureDefaultCollection()
	if err != nil {
		return NoPrompt, NoPrompt, toDBusError(err)
	}

	return coll.Path(), NoPrompt, nil
}

// SearchItems searches for items matching attributes (D-Bus method)
func (s *Service) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	// Check if vault is locked
	locked, err := s.bwClient.IsLocked(ctx)
	if err != nil {
		return nil, nil, toDBusError(err)
	}

	if locked {
		// When locked, return the collection as "locked" so clients can unlock it
		// We can't enumerate individual items, but clients can call Unlock on the collection
		return nil, []dbus.ObjectPath{DefaultCollectionPath}, nil
	}

	// Return items in unlocked, empty locked
	items, err := s.searchItemsInternal(ctx, attributes)
	if err != nil {
		return nil, nil, toDBusError(err)
	}

	return items, nil, nil
}

// searchItemsInternal performs the actual search
func (s *Service) searchItemsInternal(ctx context.Context, attributes map[string]string) ([]dbus.ObjectPath, error) {
	uri := mapping.BuildURIFromAttributes(attributes)

	var items []bitwarden.Item
	var err error

	if uri != "" {
		items, err = s.bwClient.SearchItems(ctx, uri)
	} else {
		items, err = s.bwClient.ListItems(ctx)
	}

	if err != nil {
		return nil, err
	}

	coll, _ := s.collectionManager.GetCollection(DefaultCollectionPath)

	var results []dbus.ObjectPath
	for _, item := range items {
		if mapping.MatchesAttributes(&item, attributes) {
			itemCopy := item
			dbusItem, err := s.itemManager.GetOrCreateItem(&itemCopy, coll)
			if err != nil {
				continue
			}
			results = append(results, dbusItem.Path())
		}
	}

	return results, nil
}

// Unlock unlocks the specified objects (D-Bus method)
func (s *Service) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	// Check if already unlocked
	locked, err := s.bwClient.IsLocked(ctx)
	if err != nil {
		return nil, NoPrompt, toDBusError(err)
	}

	if !locked {
		// Already unlocked, return all objects
		return objects, NoPrompt, nil
	}

	// Create a prompt for unlocking
	prompt, err := s.promptManager.CreateUnlockPrompt(objects)
	if err != nil {
		return nil, NoPrompt, toDBusError(err)
	}

	return nil, prompt.Path(), nil
}

// Lock locks the specified objects (D-Bus method)
func (s *Service) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	if err := s.bwClient.Lock(ctx); err != nil {
		return nil, NoPrompt, toDBusError(err)
	}

	return objects, NoPrompt, nil
}

// GetSecrets gets secrets for multiple items (D-Bus method)
func (s *Service) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	// Validate session
	if _, ok := s.sessionManager.GetSession(session); !ok {
		return nil, &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}

	ctx := context.Background()

	// Trigger auto-unlock if needed
	if err := s.bwClient.EnsureUnlocked(ctx); err != nil {
		if errors.Is(err, bitwarden.ErrUserCancelled) || errors.Is(err, bitwarden.ErrVaultLocked) {
			return nil, &dbus.Error{Name: ErrIsLocked, Body: []interface{}{"Vault is locked"}}
		}
		return nil, toDBusError(err)
	}

	secrets := make(map[dbus.ObjectPath]Secret)

	for _, itemPath := range items {
		item, ok := s.itemManager.GetItem(itemPath)
		if !ok {
			continue
		}

		secret, dbusErr := item.GetSecret(session)
		if dbusErr != nil {
			continue
		}

		secrets[itemPath] = secret
	}

	return secrets, nil
}

// ReadAlias returns the collection for the given alias (D-Bus method)
func (s *Service) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	if name == "default" {
		return s.collectionManager.GetDefaultAlias(), nil
	}
	return NoPrompt, nil
}

// SetAlias sets the collection for the given alias (D-Bus method)
func (s *Service) SetAlias(name string, collection dbus.ObjectPath) *dbus.Error {
	// We don't support setting aliases
	return nil
}

// Get implements org.freedesktop.DBus.Properties.Get
func (s *Service) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != ServiceInterface {
		return dbus.Variant{}, toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	switch property {
	case "Collections":
		paths := s.collectionManager.GetCollectionPaths()
		return dbus.MakeVariant(paths), nil

	default:
		return dbus.Variant{}, toDBusError(fmt.Errorf("unknown property: %s", property))
	}
}

// Set implements org.freedesktop.DBus.Properties.Set
func (s *Service) Set(iface, property string, value dbus.Variant) *dbus.Error {
	return toDBusError(fmt.Errorf("property %s is read-only", property))
}

// GetAll implements org.freedesktop.DBus.Properties.GetAll
func (s *Service) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	if iface != ServiceInterface {
		return nil, toDBusError(fmt.Errorf("unknown interface: %s", iface))
	}

	props := map[string]dbus.Variant{
		"Collections": dbus.MakeVariant(s.collectionManager.GetCollectionPaths()),
	}

	return props, nil
}
