package mapping

import (
	"strings"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// Common attribute keys used by libsecret clients
const (
	AttrService  = "service"
	AttrUsername = "username"
	AttrUser     = "user"
	AttrDomain   = "domain"
	AttrServer   = "server"
	AttrProtocol = "protocol"
	AttrPort     = "port"
	AttrPath     = "path"
	AttrSchema   = "xdg:schema"
)

// Common schemas
const (
	SchemaGenericSecret   = "org.freedesktop.Secret.Generic"
	SchemaNetworkPassword = "org.gnome.keyring.NetworkPassword"
)

// ItemToAttributes converts a Bitwarden item to libsecret attributes
func ItemToAttributes(item *bitwarden.Item) map[string]string {
	attrs := make(map[string]string)

	if item.Login != nil {
		if item.Login.Username != nil {
			attrs[AttrUsername] = *item.Login.Username
		}

		// Use the first URI as the service/domain
		if len(item.Login.URIs) > 0 {
			uri := item.Login.URIs[0].URI
			attrs[AttrService] = uri
			attrs[AttrDomain] = extractDomain(uri)
		}
	}

	// Add item name as a searchable attribute
	attrs["label"] = item.Name

	// Add schema
	attrs[AttrSchema] = SchemaGenericSecret

	// Add custom fields as attributes
	for _, field := range item.Fields {
		if field.Type == 0 { // text field
			attrs[field.Name] = field.Value
		}
	}

	return attrs
}

// MatchesAttributes checks if a Bitwarden item matches the given attributes
func MatchesAttributes(item *bitwarden.Item, attrs map[string]string) bool {
	// Only match login items for now
	if item.Login == nil {
		return false
	}

	for key, value := range attrs {
		switch key {
		case AttrSchema:
			// Skip schema matching for now - we handle all schemas
			continue

		case AttrService, AttrDomain, AttrServer:
			// Match against URIs
			if !matchesURI(item, value) {
				return false
			}

		case AttrUsername, AttrUser:
			// Match against username
			if item.Login.Username == nil || *item.Login.Username != value {
				return false
			}

		case "label":
			// Match against item name
			if !strings.EqualFold(item.Name, value) {
				return false
			}

		default:
			// Check custom fields
			if !matchesField(item, key, value) {
				return false
			}
		}
	}

	return true
}

// matchesURI checks if any of the item's URIs match the given value
func matchesURI(item *bitwarden.Item, value string) bool {
	if item.Login == nil {
		return false
	}

	valueLower := strings.ToLower(value)
	valueDomain := extractDomain(value)

	for _, uri := range item.Login.URIs {
		uriLower := strings.ToLower(uri.URI)
		uriDomain := extractDomain(uri.URI)

		// Exact match
		if uriLower == valueLower {
			return true
		}

		// Domain match
		if valueDomain != "" && uriDomain == valueDomain {
			return true
		}

		// Contains match (for partial URLs)
		if strings.Contains(uriLower, valueLower) || strings.Contains(valueLower, uriLower) {
			return true
		}
	}

	return false
}

// matchesField checks if an item has a custom field matching the given key/value
func matchesField(item *bitwarden.Item, key, value string) bool {
	for _, field := range item.Fields {
		if field.Name == key && field.Value == value {
			return true
		}
	}
	return false
}

// extractDomain extracts the domain from a URL or returns the input if not a URL
func extractDomain(uri string) string {
	// Remove protocol
	uri = strings.TrimPrefix(uri, "https://")
	uri = strings.TrimPrefix(uri, "http://")

	// Remove path
	if idx := strings.Index(uri, "/"); idx != -1 {
		uri = uri[:idx]
	}

	// Remove port
	if idx := strings.Index(uri, ":"); idx != -1 {
		uri = uri[:idx]
	}

	return strings.ToLower(uri)
}

// BuildURIFromAttributes constructs a URI from libsecret attributes
func BuildURIFromAttributes(attrs map[string]string) string {
	// Try service first
	if service, ok := attrs[AttrService]; ok && service != "" {
		return normalizeURI(service)
	}

	// Try domain/server
	domain := ""
	if d, ok := attrs[AttrDomain]; ok {
		domain = d
	} else if s, ok := attrs[AttrServer]; ok {
		domain = s
	}

	if domain == "" {
		return ""
	}

	// Add protocol if specified
	protocol := "https"
	if p, ok := attrs[AttrProtocol]; ok {
		protocol = p
	}

	uri := protocol + "://" + domain

	// Add port if specified
	if port, ok := attrs[AttrPort]; ok && port != "" {
		uri += ":" + port
	}

	// Add path if specified
	if path, ok := attrs[AttrPath]; ok && path != "" {
		if !strings.HasPrefix(path, "/") {
			uri += "/"
		}
		uri += path
	}

	return uri
}

// normalizeURI ensures a URI has a protocol prefix
func normalizeURI(uri string) string {
	if !strings.Contains(uri, "://") {
		return "https://" + uri
	}
	return uri
}

// GetUsername extracts username from attributes
func GetUsername(attrs map[string]string) string {
	if u, ok := attrs[AttrUsername]; ok {
		return u
	}
	if u, ok := attrs[AttrUser]; ok {
		return u
	}
	return ""
}
