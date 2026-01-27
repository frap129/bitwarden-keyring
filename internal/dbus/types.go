package dbus

import (
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	// D-Bus bus name and paths
	BusName        = "org.freedesktop.secrets"
	ServicePath    = dbus.ObjectPath("/org/freedesktop/secrets")
	CollectionPath = "/org/freedesktop/secrets/collections/"
	SessionPath    = "/org/freedesktop/secrets/session/"
	PromptPath     = "/org/freedesktop/secrets/prompt/"
	AliasPath      = "/org/freedesktop/secrets/aliases/"

	// Interface names
	ServiceInterface    = "org.freedesktop.Secret.Service"
	CollectionInterface = "org.freedesktop.Secret.Collection"
	ItemInterface       = "org.freedesktop.Secret.Item"
	SessionInterface    = "org.freedesktop.Secret.Session"
	PromptInterface     = "org.freedesktop.Secret.Prompt"
	PropertiesInterface = "org.freedesktop.DBus.Properties"

	// Error names
	ErrIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
	ErrNoSession    = "org.freedesktop.Secret.Error.NoSession"
	ErrNoSuchObject = "org.freedesktop.Secret.Error.NoSuchObject"

	// Property keys for D-Bus properties
	PropItemLabel      = "org.freedesktop.Secret.Item.Label"
	PropItemAttributes = "org.freedesktop.Secret.Item.Attributes"
	PropCollLabel      = "org.freedesktop.Secret.Collection.Label"
)

// Secret represents a secret value as defined by the Secret Service API
// D-Bus signature: (oayays)
type Secret struct {
	Session     dbus.ObjectPath // Session object path
	Parameters  []byte          // Encryption parameters (empty for plain)
	Value       []byte          // The secret value
	ContentType string          // MIME type
}

// NoPrompt is the object path indicating no prompt is needed
var NoPrompt = dbus.ObjectPath("/")

// DefaultCollectionPath is the path to the default collection
var DefaultCollectionPath = dbus.ObjectPath(CollectionPath + "default")

// SanitizeID removes hyphens from UUIDs to make them valid D-Bus object path components
// D-Bus object paths can only contain [A-Za-z0-9_]
func SanitizeID(id string) string {
	return strings.ReplaceAll(id, "-", "")
}

// UnsanitizeID restores hyphens to a sanitized UUID
func UnsanitizeID(sanitized string) string {
	if len(sanitized) != 32 {
		return sanitized // Not a UUID, return as-is
	}
	// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return sanitized[0:8] + "-" + sanitized[8:12] + "-" + sanitized[12:16] + "-" + sanitized[16:20] + "-" + sanitized[20:32]
}
