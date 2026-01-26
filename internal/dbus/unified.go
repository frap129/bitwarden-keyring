package dbus

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/joe/bitwarden-keyring/internal/bitwarden"
	"github.com/joe/bitwarden-keyring/internal/mapping"
)

// UnifiedService handles all D-Bus method calls for the Secret Service API
type UnifiedService struct {
	conn     *dbus.Conn
	bwClient *bitwarden.Client

	sessions   map[dbus.ObjectPath]*Session
	sessionCtr uint64
	sessionMu  sync.RWMutex

	promptCtr uint64
	promptMu  sync.Mutex

	mu sync.RWMutex
}

// NewUnifiedService creates a new unified service handler
func NewUnifiedService(conn *dbus.Conn, bwClient *bitwarden.Client) *UnifiedService {
	return &UnifiedService{
		conn:     conn,
		bwClient: bwClient,
		sessions: make(map[dbus.ObjectPath]*Session),
	}
}

// Export exports the service to D-Bus using subtree handling
func (s *UnifiedService) Export() error {
	// Export to all interfaces we implement at the root path
	// Using ExportSubtree to handle all paths under /org/freedesktop/secrets
	if err := s.conn.ExportSubtree(s, ServicePath, ServiceInterface); err != nil {
		return fmt.Errorf("failed to export Service interface: %w", err)
	}

	if err := s.conn.ExportSubtree(s, ServicePath, CollectionInterface); err != nil {
		return fmt.Errorf("failed to export Collection interface: %w", err)
	}

	if err := s.conn.ExportSubtree(s, ServicePath, ItemInterface); err != nil {
		return fmt.Errorf("failed to export Item interface: %w", err)
	}

	if err := s.conn.ExportSubtree(s, ServicePath, SessionInterface); err != nil {
		return fmt.Errorf("failed to export Session interface: %w", err)
	}

	if err := s.conn.ExportSubtree(s, ServicePath, PromptInterface); err != nil {
		return fmt.Errorf("failed to export Prompt interface: %w", err)
	}

	if err := s.conn.ExportSubtree(s, ServicePath, PropertiesInterface); err != nil {
		return fmt.Errorf("failed to export Properties interface: %w", err)
	}

	if err := s.conn.ExportSubtree(introspectHandler{s}, ServicePath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return fmt.Errorf("failed to export Introspectable: %w", err)
	}

	// Request the bus name
	reply, err := s.conn.RequestName(BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		return fmt.Errorf("failed to request bus name: %w", err)
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("bus name %s already taken", BusName)
	}

	log.Printf("Exported Secret Service at %s", BusName)
	return nil
}

// introspectHandler handles introspection requests based on path
type introspectHandler struct {
	s *UnifiedService
}

func (h introspectHandler) Introspect() (string, *dbus.Error) {
	// This will be called with the message context - we return service XML
	// The actual path-specific introspection is handled below
	return ServiceIntrospectXML, nil
}

// Helper to get the message path from context (godbus ExportSubtree provides this)
func getMessagePath(msg *dbus.Message) dbus.ObjectPath {
	return msg.Headers[dbus.FieldPath].Value().(dbus.ObjectPath)
}

// ============== Service Methods ==============

// OpenSession opens a new session (D-Bus method)
func (s *UnifiedService) OpenSession(algorithm string, input dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	s.sessionCtr++
	path := dbus.ObjectPath(fmt.Sprintf("%s%d", SessionPath, s.sessionCtr))

	var aesKey []byte
	var output dbus.Variant

	// Extract input bytes
	var inputBytes []byte
	if input.Value() != nil {
		switch v := input.Value().(type) {
		case []byte:
			inputBytes = v
		case string:
			inputBytes = []byte(v)
		}
	}

	switch algorithm {
	case AlgorithmPlain:
		output = dbus.MakeVariant("")

	case AlgorithmDH:
		group := rfc2409SecondOakleyGroup()
		private, public, err := group.NewKeypair()
		if err != nil {
			return dbus.Variant{}, NoPrompt, dbus.MakeFailedError(err)
		}
		output = dbus.MakeVariant(public.Bytes())

		theirPublic := new(big.Int).SetBytes(inputBytes)
		aesKey, err = group.keygenHKDFSHA256AES128(theirPublic, private)
		if err != nil {
			return dbus.Variant{}, NoPrompt, dbus.MakeFailedError(err)
		}

	default:
		return dbus.Variant{}, NoPrompt, dbus.MakeFailedError(fmt.Errorf("unsupported algorithm: %s", algorithm))
	}

	session := &Session{
		conn:      s.conn,
		path:      path,
		algorithm: algorithm,
		aesKey:    aesKey,
	}
	s.sessions[path] = session

	return output, path, nil
}

// CreateCollection creates a new collection (D-Bus method)
func (s *UnifiedService) CreateCollection(properties map[string]dbus.Variant, alias string) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	return DefaultCollectionPath, NoPrompt, nil
}

// SearchItems searches for items matching attributes (D-Bus method)
func (s *UnifiedService) SearchItems(attributes map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	locked, err := s.bwClient.IsLocked(ctx)
	if err != nil {
		return nil, nil, dbus.MakeFailedError(err)
	}

	// If vault is locked, try to unlock it first
	if locked {
		log.Printf("Vault is locked, prompting for password...")
		password, err := s.bwClient.SessionManager().PromptForPassword()
		if err != nil {
			log.Printf("Failed to prompt for password: %v", err)
			// Return empty results - vault is locked
			return make([]dbus.ObjectPath, 0), make([]dbus.ObjectPath, 0), nil
		}

		_, err = s.bwClient.Unlock(ctx, password)
		if err != nil {
			log.Printf("Failed to unlock vault: %v", err)
			return make([]dbus.ObjectPath, 0), make([]dbus.ObjectPath, 0), nil
		}
		log.Printf("Vault unlocked successfully")
	}

	items, err := s.findMatchingItems(ctx, attributes)
	if err != nil {
		return nil, nil, dbus.MakeFailedError(err)
	}

	return items, make([]dbus.ObjectPath, 0), nil
}

func (s *UnifiedService) findMatchingItems(ctx context.Context, attributes map[string]string) ([]dbus.ObjectPath, error) {
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

	results := make([]dbus.ObjectPath, 0)
	for _, item := range items {
		if item.ID == "" {
			continue // Skip items without IDs
		}
		if mapping.MatchesAttributes(&item, attributes) {
			results = append(results, ItemPathFromID(item.ID))
		}
	}
	return results, nil
}

// Unlock unlocks the specified objects (D-Bus method)
func (s *UnifiedService) Unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	locked, err := s.bwClient.IsLocked(ctx)
	if err != nil {
		return nil, NoPrompt, dbus.MakeFailedError(err)
	}

	if !locked {
		return objects, NoPrompt, nil
	}

	// Create a prompt
	s.promptMu.Lock()
	s.promptCtr++
	promptPath := dbus.ObjectPath(fmt.Sprintf("%s%d", PromptPath, s.promptCtr))
	s.promptMu.Unlock()

	// Store prompt info for later
	// For now, just return the prompt path
	return nil, promptPath, nil
}

// Lock locks the specified objects (D-Bus method)
func (s *UnifiedService) Lock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	ctx := context.Background()

	if err := s.bwClient.Lock(ctx); err != nil {
		return nil, NoPrompt, dbus.MakeFailedError(err)
	}

	return objects, NoPrompt, nil
}

// GetSecrets gets secrets for multiple items (D-Bus method)
func (s *UnifiedService) GetSecrets(items []dbus.ObjectPath, session dbus.ObjectPath) (map[dbus.ObjectPath]Secret, *dbus.Error) {
	s.sessionMu.RLock()
	sess, ok := s.sessions[session]
	s.sessionMu.RUnlock()

	if !ok {
		return nil, &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}

	ctx := context.Background()

	// Check if vault is locked and try to unlock
	locked, err := s.bwClient.IsLocked(ctx)
	if err != nil {
		return nil, dbus.MakeFailedError(err)
	}

	if locked {
		// Try to unlock the vault
		log.Printf("Vault is locked, prompting for password...")
		password, err := s.bwClient.SessionManager().PromptForPassword()
		if err != nil {
			log.Printf("Failed to prompt for password: %v", err)
			return nil, &dbus.Error{Name: ErrIsLocked, Body: []interface{}{"Failed to prompt for password"}}
		}

		_, err = s.bwClient.Unlock(ctx, password)
		if err != nil {
			log.Printf("Failed to unlock vault: %v", err)
			return nil, &dbus.Error{Name: ErrIsLocked, Body: []interface{}{"Failed to unlock vault"}}
		}
		log.Printf("Vault unlocked successfully")
	}

	secrets := make(map[dbus.ObjectPath]Secret)

	for _, itemPath := range items {
		itemID := extractItemID(itemPath)
		if itemID == "" {
			continue
		}

		bwItem, err := s.bwClient.GetItem(ctx, itemID)
		if err != nil || bwItem.Login == nil || bwItem.Login.Password == nil {
			continue
		}

		plaintext := []byte(*bwItem.Login.Password)
		value, params, err := sess.EncryptSecret(plaintext)
		if err != nil {
			continue
		}

		secrets[itemPath] = Secret{
			Session:     session,
			Parameters:  params,
			Value:       value,
			ContentType: "text/plain",
		}
	}

	return secrets, nil
}

// ReadAlias returns the collection for the given alias (D-Bus method)
func (s *UnifiedService) ReadAlias(name string) (dbus.ObjectPath, *dbus.Error) {
	if name == "default" {
		return DefaultCollectionPath, nil
	}
	return dbus.ObjectPath("/"), nil
}

// SetAlias sets the collection for the given alias (D-Bus method)
func (s *UnifiedService) SetAlias(name string, collection dbus.ObjectPath) *dbus.Error {
	return nil
}

// ============== Collection Methods ==============

// Delete deletes the collection (D-Bus method for Collection)
func (s *UnifiedService) Delete() (dbus.ObjectPath, *dbus.Error) {
	return NoPrompt, dbus.MakeFailedError(fmt.Errorf("cannot delete default collection"))
}

// CreateItem creates a new item in the collection (D-Bus method)
func (s *UnifiedService) CreateItem(properties map[string]dbus.Variant, secret Secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	s.sessionMu.RLock()
	sess, ok := s.sessions[secret.Session]
	s.sessionMu.RUnlock()

	if !ok {
		return NoPrompt, NoPrompt, &dbus.Error{Name: ErrNoSession, Body: []interface{}{"Invalid session"}}
	}

	decryptedValue, err := sess.DecryptSecret(secret.Value, secret.Parameters)
	if err != nil {
		return NoPrompt, NoPrompt, dbus.MakeFailedError(fmt.Errorf("failed to decrypt secret: %w", err))
	}

	ctx := context.Background()

	// Check if vault is locked and try to unlock
	locked, err := s.bwClient.IsLocked(ctx)
	if err != nil {
		return NoPrompt, NoPrompt, dbus.MakeFailedError(fmt.Errorf("failed to check lock status: %w", err))
	}

	if locked {
		// Try to unlock the vault
		log.Printf("Vault is locked, prompting for password...")
		password, err := s.bwClient.SessionManager().PromptForPassword()
		if err != nil {
			log.Printf("Failed to prompt for password: %v", err)
			return NoPrompt, NoPrompt, dbus.MakeFailedError(fmt.Errorf("failed to prompt for password: %w", err))
		}

		log.Printf("Got password, attempting unlock...")
		_, err = s.bwClient.Unlock(ctx, password)
		if err != nil {
			log.Printf("Failed to unlock vault: %v", err)
			return NoPrompt, NoPrompt, dbus.MakeFailedError(fmt.Errorf("failed to unlock vault: %w", err))
		}
		log.Printf("Vault unlocked successfully")
	}

	// Extract label
	label := "Unnamed"
	if labelVar, ok := properties["org.freedesktop.Secret.Item.Label"]; ok {
		if l, ok := labelVar.Value().(string); ok {
			label = l
		}
	}

	// Extract attributes
	var attrs map[string]string
	if attrsVar, ok := properties["org.freedesktop.Secret.Item.Attributes"]; ok {
		if a, ok := attrsVar.Value().(map[string]string); ok {
			attrs = a
		}
	}

	uri := mapping.BuildURIFromAttributes(attrs)
	username := mapping.GetUsername(attrs)

	// If replace, try to find existing
	if replace && attrs != nil {
		items, _ := s.bwClient.ListItems(ctx)
		for _, item := range items {
			if mapping.MatchesAttributes(&item, attrs) {
				password := string(decryptedValue)
				item.Login.Password = &password
				item.Name = label

				req := bitwarden.CreateItemRequest{
					Type:     bitwarden.ItemTypeLogin,
					Name:     label,
					FolderID: item.FolderID,
					Login:    item.Login,
					Fields:   item.Fields,
				}

				updated, err := s.bwClient.UpdateItem(ctx, item.ID, req)
				if err != nil {
					return NoPrompt, NoPrompt, dbus.MakeFailedError(err)
				}

				return ItemPathFromID(updated.ID), NoPrompt, nil
			}
		}
	}

	// Create new item
	password := string(decryptedValue)
	login := &bitwarden.Login{Password: &password}

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

	created, err := s.bwClient.CreateItem(ctx, req)
	if err != nil {
		return NoPrompt, NoPrompt, dbus.MakeFailedError(err)
	}

	log.Printf("Created item with ID: %q", created.ID)
	itemPath := ItemPathFromID(created.ID)
	log.Printf("Item path: %s", itemPath)

	return itemPath, NoPrompt, nil
}

// ============== Item Methods ==============

// GetSecret returns the item's secret (D-Bus method)
func (s *UnifiedService) GetSecret(session dbus.ObjectPath) (Secret, *dbus.Error) {
	// This needs the item path from the message - we'll use a workaround
	// For now, return an error - items should use GetSecrets on the service
	return Secret{}, dbus.MakeFailedError(fmt.Errorf("use GetSecrets on the service"))
}

// SetSecret sets the item's secret (D-Bus method)
func (s *UnifiedService) SetSecret(secret Secret) *dbus.Error {
	return dbus.MakeFailedError(fmt.Errorf("not implemented"))
}

// ============== Session Methods ==============

// Close closes a session (D-Bus method)
func (s *UnifiedService) Close() *dbus.Error {
	// Session close - would need path from message
	return nil
}

// ============== Prompt Methods ==============

// Prompt triggers the prompt (D-Bus method)
func (s *UnifiedService) Prompt(windowID string) *dbus.Error {
	// Trigger unlock
	go func() {
		ctx := context.Background()
		sm := s.bwClient.SessionManager()

		password, err := sm.PromptForPassword()
		if err != nil {
			return
		}

		_, err = s.bwClient.Unlock(ctx, password)
		if err != nil {
			log.Printf("Unlock failed: %v", err)
		}
	}()
	return nil
}

// Dismiss dismisses the prompt (D-Bus method)
func (s *UnifiedService) Dismiss() *dbus.Error {
	return nil
}

// ============== Properties Methods ==============

// Get gets a property (D-Bus method)
func (s *UnifiedService) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	switch iface {
	case ServiceInterface:
		switch property {
		case "Collections":
			return dbus.MakeVariant([]dbus.ObjectPath{DefaultCollectionPath}), nil
		}

	case CollectionInterface:
		switch property {
		case "Items":
			ctx := context.Background()
			items, err := s.bwClient.ListItems(ctx)
			if err != nil {
				return dbus.Variant{}, dbus.MakeFailedError(err)
			}
			paths := make([]dbus.ObjectPath, 0, len(items))
			for _, item := range items {
				if item.Type == bitwarden.ItemTypeLogin {
					paths = append(paths, ItemPathFromID(item.ID))
				}
			}
			return dbus.MakeVariant(paths), nil

		case "Label":
			return dbus.MakeVariant("Default"), nil

		case "Locked":
			ctx := context.Background()
			locked, _ := s.bwClient.IsLocked(ctx)
			return dbus.MakeVariant(locked), nil

		case "Created", "Modified":
			return dbus.MakeVariant(uint64(0)), nil
		}

	case ItemInterface:
		switch property {
		case "Locked":
			return dbus.MakeVariant(false), nil
		case "Label":
			return dbus.MakeVariant(""), nil
		case "Attributes":
			return dbus.MakeVariant(map[string]string{}), nil
		case "Created", "Modified":
			return dbus.MakeVariant(uint64(0)), nil
		}
	}

	return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown property %s.%s", iface, property))
}

// Set sets a property (D-Bus method)
func (s *UnifiedService) Set(iface, property string, value dbus.Variant) *dbus.Error {
	return dbus.MakeFailedError(fmt.Errorf("property %s.%s is read-only", iface, property))
}

// GetAll gets all properties (D-Bus method)
func (s *UnifiedService) GetAll(iface string) (map[string]dbus.Variant, *dbus.Error) {
	switch iface {
	case ServiceInterface:
		return map[string]dbus.Variant{
			"Collections": dbus.MakeVariant([]dbus.ObjectPath{DefaultCollectionPath}),
		}, nil

	case CollectionInterface:
		ctx := context.Background()
		locked, _ := s.bwClient.IsLocked(ctx)
		items, _ := s.bwClient.ListItems(ctx)
		paths := make([]dbus.ObjectPath, 0, len(items))
		for _, item := range items {
			if item.Type == bitwarden.ItemTypeLogin {
				paths = append(paths, ItemPathFromID(item.ID))
			}
		}
		return map[string]dbus.Variant{
			"Items":    dbus.MakeVariant(paths),
			"Label":    dbus.MakeVariant("Default"),
			"Locked":   dbus.MakeVariant(locked),
			"Created":  dbus.MakeVariant(uint64(0)),
			"Modified": dbus.MakeVariant(uint64(0)),
		}, nil

	case ItemInterface:
		return map[string]dbus.Variant{
			"Locked":     dbus.MakeVariant(false),
			"Label":      dbus.MakeVariant(""),
			"Attributes": dbus.MakeVariant(map[string]string{}),
			"Created":    dbus.MakeVariant(uint64(0)),
			"Modified":   dbus.MakeVariant(uint64(0)),
		}, nil
	}

	return nil, dbus.MakeFailedError(fmt.Errorf("unknown interface: %s", iface))
}

// Helper to extract item ID from path and unsanitize it back to UUID format
func extractItemID(path dbus.ObjectPath) string {
	pathStr := string(path)
	prefix := CollectionPath + "default/"
	if strings.HasPrefix(pathStr, prefix) {
		sanitizedID := pathStr[len(prefix):]
		return UnsanitizeID(sanitizedID)
	}
	return ""
}
