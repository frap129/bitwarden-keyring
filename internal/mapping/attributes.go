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

			// Extract URI components for round-trip compatibility
			protocol, port, path := extractURIComponents(uri)
			if protocol != "" {
				attrs[AttrProtocol] = protocol
			}
			if port != "" {
				attrs[AttrPort] = port
			}
			if path != "" && path != "/" {
				attrs[AttrPath] = path
			}
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

		case AttrProtocol:
			// Match protocol against URI scheme
			if len(item.Login.URIs) == 0 {
				return false
			}
			uri := item.Login.URIs[0].URI
			if !strings.HasPrefix(strings.ToLower(uri), strings.ToLower(value)+"://") {
				return false
			}

		case AttrPort:
			// Match port against URI
			if len(item.Login.URIs) == 0 {
				return false
			}
			uri := item.Login.URIs[0].URI
			if !matchesPort(uri, value) {
				return false
			}

		case AttrPath:
			// Match path against URI
			if len(item.Login.URIs) == 0 {
				return false
			}
			uri := item.Login.URIs[0].URI
			if !matchesPath(uri, value) {
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

// matchesPort checks if a URI contains the given port
func matchesPort(uri, port string) bool {
	// Extract host:port portion from URI
	u := uri
	// Remove protocol
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Remove path
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	// Handle IPv6 addresses (e.g., [::1]:8080)
	if strings.HasPrefix(u, "[") {
		// IPv6 address - look for ]:port
		if idx := strings.Index(u, "]:"); idx != -1 {
			uriPort := u[idx+2:]
			return uriPort == port
		}
		// No port after IPv6 address
	} else if idx := strings.LastIndex(u, ":"); idx != -1 {
		// IPv4 or hostname with port
		uriPort := u[idx+1:]
		return uriPort == port
	}
	// No port in URI - check for default ports
	if strings.HasPrefix(strings.ToLower(uri), "https://") && port == "443" {
		return true
	}
	if strings.HasPrefix(strings.ToLower(uri), "http://") && port == "80" {
		return true
	}
	return false
}

// matchesPath checks if a URI contains the given path (exact match per Secret Service spec)
func matchesPath(uri, path string) bool {
	// Extract path portion from URI
	u := uri
	// Remove protocol
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Find path start
	if idx := strings.Index(u, "/"); idx != -1 {
		uriPath := u[idx:]
		// Normalize paths for comparison
		expectedPath := path
		if !strings.HasPrefix(expectedPath, "/") {
			expectedPath = "/" + expectedPath
		}
		// Exact match: paths must match exactly, or URI path must be a sub-path
		// (e.g., expectedPath="/api" matches uriPath="/api" or "/api/v1", but not "/api2")
		return uriPath == expectedPath || strings.HasPrefix(uriPath, expectedPath+"/")
	}
	// No path in URI - only match if expected path is empty or "/"
	return path == "" || path == "/"
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

	// Handle IPv6 addresses (e.g., [::1]:8080)
	if strings.HasPrefix(uri, "[") {
		// Find closing bracket
		if idx := strings.Index(uri, "]"); idx != -1 {
			// Return the bracketed IPv6 address without port
			return strings.ToLower(uri[:idx+1])
		}
		// Malformed IPv6, return as-is
		return strings.ToLower(uri)
	}

	// Remove port for non-IPv6 (use LastIndex to handle edge cases)
	if idx := strings.LastIndex(uri, ":"); idx != -1 {
		uri = uri[:idx]
	}

	return strings.ToLower(uri)
}

// extractURIComponents extracts protocol, port, and path from a URI
func extractURIComponents(uri string) (protocol, port, path string) {
	// Extract protocol
	if idx := strings.Index(uri, "://"); idx != -1 {
		protocol = uri[:idx]
		uri = uri[idx+3:]
	}

	// Extract path (everything after first /)
	// For IPv6, path comes after the closing bracket
	if idx := strings.Index(uri, "/"); idx != -1 {
		path = uri[idx:]
		uri = uri[:idx]
	}

	// Extract port - handle IPv6 addresses (e.g., [::1]:8080)
	if strings.HasPrefix(uri, "[") {
		// IPv6 address - look for ]:port
		if idx := strings.Index(uri, "]:"); idx != -1 {
			port = uri[idx+2:]
		}
	} else if idx := strings.LastIndex(uri, ":"); idx != -1 {
		// IPv4 or hostname with port
		port = uri[idx+1:]
	}

	return protocol, port, path
}

// BuildURIFromAttributes constructs a URI from libsecret attributes
func BuildURIFromAttributes(attrs map[string]string) string {
	// Try service first
	if service, ok := attrs[AttrService]; ok && service != "" {
		// If service already has a scheme, use as-is
		if strings.Contains(service, "://") {
			return service
		}
		// Otherwise, treat as hostname and build full URI with components
		protocol := "https"
		if p, ok := attrs[AttrProtocol]; ok && p != "" {
			protocol = p
		}
		uri := protocol + "://" + service
		// Only add port if service doesn't already contain a port
		if port, ok := attrs[AttrPort]; ok && port != "" {
			// Check if service already has a port (hostname:port pattern)
			// Handle IPv6 (e.g., [::1]:8080) by checking after brackets
			hasPort := false
			if strings.HasPrefix(service, "[") {
				// IPv6: check for port after closing bracket
				if idx := strings.Index(service, "]:"); idx != -1 {
					hasPort = true
				}
			} else if strings.Contains(service, ":") {
				hasPort = true
			}
			if !hasPort {
				uri += ":" + port
			}
		}
		if path, ok := attrs[AttrPath]; ok && path != "" {
			if !strings.HasPrefix(path, "/") {
				uri += "/"
			}
			uri += path
		}
		return uri
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

// ReservedAttributes are system attributes that should not be stored as custom fields
var ReservedAttributes = map[string]bool{
	"label":    true,
	AttrSchema: true,
	"created":  true,
	"modified": true,
	"locked":   true,
}

// UpdateItemFromAttributes updates a Bitwarden item with D-Bus attributes.
// It maps known attributes to their corresponding Bitwarden fields and stores
// unknown attributes as custom fields.
// Note: This merges attributes (adds/updates) rather than replacing.
func UpdateItemFromAttributes(item *bitwarden.Item, attrs map[string]string) {
	// Track which attributes we've handled to avoid duplicate URI processing
	handledURI := false

	// Handle username with explicit precedence: AttrUsername takes priority over AttrUser
	if username, ok := attrs[AttrUsername]; ok {
		if item.Login == nil {
			item.Login = &bitwarden.Login{}
		}
		item.Login.Username = &username
	} else if user, ok := attrs[AttrUser]; ok {
		if item.Login == nil {
			item.Login = &bitwarden.Login{}
		}
		item.Login.Username = &user
	}

	for key, value := range attrs {
		switch key {
		case AttrUsername, AttrUser:
			// Already handled above with deterministic precedence
			continue

		case AttrService, AttrDomain, AttrServer:
			// Only process URI once even if multiple URI-related attrs present
			if !handledURI {
				uri := BuildURIFromAttributes(attrs)
				if uri != "" {
					if item.Login == nil {
						item.Login = &bitwarden.Login{}
					}
					if len(item.Login.URIs) > 0 {
						item.Login.URIs[0].URI = uri
					} else {
						item.Login.URIs = []bitwarden.URI{{URI: uri}}
					}
				}
				handledURI = true
			}

		case AttrProtocol, AttrPort, AttrPath:
			// These are handled as part of URI building, skip individual processing
			continue

		default:
			if ReservedAttributes[key] {
				continue // Skip system attributes
			}
			updateOrAddField(item, key, value)
		}
	}
}

// updateOrAddField updates an existing custom field or adds a new one
func updateOrAddField(item *bitwarden.Item, name, value string) {
	// Find existing field with same name
	for i, f := range item.Fields {
		if f.Name == name {
			item.Fields[i].Value = value
			return
		}
	}
	// Add new field
	item.Fields = append(item.Fields, bitwarden.Field{
		Name:  name,
		Value: value,
		Type:  0, // text
	})
}
