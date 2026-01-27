package mapping

import (
	"testing"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

func TestUpdateItemFromAttributes(t *testing.T) {
	tests := []struct {
		name     string
		initial  *bitwarden.Item
		attrs    map[string]string
		validate func(*testing.T, *bitwarden.Item)
	}{
		{
			name:    "updates username",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}},
			attrs:   map[string]string{"username": "newuser"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if i.Login.Username == nil || *i.Login.Username != "newuser" {
					t.Errorf("expected username 'newuser', got %v", i.Login.Username)
				}
			},
		},
		{
			name:    "updates user attr same as username",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}},
			attrs:   map[string]string{"user": "testuser"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if i.Login.Username == nil || *i.Login.Username != "testuser" {
					t.Errorf("expected username 'testuser', got %v", i.Login.Username)
				}
			},
		},
		{
			name:    "adds custom field",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}},
			attrs:   map[string]string{"custom_key": "custom_value"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if len(i.Fields) != 1 {
					t.Errorf("expected 1 field, got %d", len(i.Fields))
					return
				}
				if i.Fields[0].Name != "custom_key" || i.Fields[0].Value != "custom_value" {
					t.Errorf("expected field custom_key=custom_value, got %s=%s", i.Fields[0].Name, i.Fields[0].Value)
				}
			},
		},
		{
			name:    "skips reserved attributes",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}},
			attrs:   map[string]string{"xdg:schema": "should.be.ignored", "label": "also.ignored"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if len(i.Fields) != 0 {
					t.Errorf("expected 0 fields, got %d", len(i.Fields))
				}
			},
		},
		{
			name:    "builds URI from domain",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}},
			attrs:   map[string]string{"domain": "example.com"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if len(i.Login.URIs) != 1 {
					t.Errorf("expected 1 URI, got %d", len(i.Login.URIs))
					return
				}
				if i.Login.URIs[0].URI != "https://example.com" {
					t.Errorf("expected URI 'https://example.com', got '%s'", i.Login.URIs[0].URI)
				}
			},
		},
		{
			name:    "builds URI with port and path",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}},
			attrs:   map[string]string{"server": "example.com", "port": "8080", "path": "/api"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if len(i.Login.URIs) != 1 {
					t.Errorf("expected 1 URI, got %d", len(i.Login.URIs))
					return
				}
				expected := "https://example.com:8080/api"
				if i.Login.URIs[0].URI != expected {
					t.Errorf("expected URI '%s', got '%s'", expected, i.Login.URIs[0].URI)
				}
			},
		},
		{
			name:    "updates existing field",
			initial: &bitwarden.Item{Login: &bitwarden.Login{}, Fields: []bitwarden.Field{{Name: "existing", Value: "old", Type: 0}}},
			attrs:   map[string]string{"existing": "new"},
			validate: func(t *testing.T, i *bitwarden.Item) {
				if len(i.Fields) != 1 {
					t.Errorf("expected 1 field, got %d", len(i.Fields))
					return
				}
				if i.Fields[0].Value != "new" {
					t.Errorf("expected field value 'new', got '%s'", i.Fields[0].Value)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			UpdateItemFromAttributes(tt.initial, tt.attrs)
			tt.validate(t, tt.initial)
		})
	}
}

func TestMatchesAttributes_URIComponents(t *testing.T) {
	tests := []struct {
		name    string
		item    *bitwarden.Item
		attrs   map[string]string
		matches bool
	}{
		{
			name: "matches protocol https",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com:8080/path"}},
				},
			},
			attrs:   map[string]string{"protocol": "https"},
			matches: true,
		},
		{
			name: "does not match wrong protocol",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com"}},
				},
			},
			attrs:   map[string]string{"protocol": "http"},
			matches: false,
		},
		{
			name: "matches port",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com:8080/path"}},
				},
			},
			attrs:   map[string]string{"port": "8080"},
			matches: true,
		},
		{
			name: "does not match wrong port",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com:8080"}},
				},
			},
			attrs:   map[string]string{"port": "443"},
			matches: false,
		},
		{
			name: "matches default https port",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com"}},
				},
			},
			attrs:   map[string]string{"port": "443"},
			matches: true,
		},
		{
			name: "matches IPv6 port",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://[::1]:8080/path"}},
				},
			},
			attrs:   map[string]string{"port": "8080"},
			matches: true,
		},
		{
			name: "matches path with sub-path",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com:8080/api/v1"}},
				},
			},
			attrs:   map[string]string{"path": "/api"},
			matches: true,
		},
		{
			name: "does not match path prefix without separator",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com/api2"}},
				},
			},
			attrs:   map[string]string{"path": "/api"},
			matches: false,
		},
		{
			name: "matches exact path",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com/api"}},
				},
			},
			attrs:   map[string]string{"path": "/api"},
			matches: true,
		},
		{
			name: "matches domain",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					URIs: []bitwarden.URI{{URI: "https://example.com:8080/path"}},
				},
			},
			attrs:   map[string]string{"domain": "example.com"},
			matches: true,
		},
		{
			name: "matches username",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					Username: strPtr("testuser"),
					URIs:     []bitwarden.URI{{URI: "https://example.com"}},
				},
			},
			attrs:   map[string]string{"username": "testuser"},
			matches: true,
		},
		{
			name: "does not match wrong username",
			item: &bitwarden.Item{
				Login: &bitwarden.Login{
					Username: strPtr("testuser"),
					URIs:     []bitwarden.URI{{URI: "https://example.com"}},
				},
			},
			attrs:   map[string]string{"username": "otheruser"},
			matches: false,
		},
		{
			name: "matches custom field",
			item: &bitwarden.Item{
				Login:  &bitwarden.Login{URIs: []bitwarden.URI{{URI: "https://example.com"}}},
				Fields: []bitwarden.Field{{Name: "custom", Value: "value", Type: 0}},
			},
			attrs:   map[string]string{"custom": "value"},
			matches: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesAttributes(tt.item, tt.attrs)
			if got != tt.matches {
				t.Errorf("MatchesAttributes() = %v, want %v", got, tt.matches)
			}
		})
	}
}

func TestItemToAttributes_ExtractsURIComponents(t *testing.T) {
	item := &bitwarden.Item{
		Name: "Test Item",
		Login: &bitwarden.Login{
			Username: strPtr("testuser"),
			URIs:     []bitwarden.URI{{URI: "https://example.com:8080/api/v1"}},
		},
	}

	attrs := ItemToAttributes(item)

	tests := []struct {
		key      string
		expected string
	}{
		{"username", "testuser"},
		{"service", "https://example.com:8080/api/v1"},
		{"domain", "example.com"},
		{"protocol", "https"},
		{"port", "8080"},
		{"path", "/api/v1"},
		{"label", "Test Item"},
		{"xdg:schema", SchemaGenericSecret},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got, ok := attrs[tt.key]
			if !ok {
				t.Errorf("expected attribute '%s' to exist", tt.key)
				return
			}
			if got != tt.expected {
				t.Errorf("attrs[%s] = '%s', want '%s'", tt.key, got, tt.expected)
			}
		})
	}
}

func TestExtractURIComponents(t *testing.T) {
	tests := []struct {
		uri      string
		protocol string
		port     string
		path     string
	}{
		{"https://example.com", "https", "", ""},
		{"https://example.com:8080", "https", "8080", ""},
		{"https://example.com/path", "https", "", "/path"},
		{"https://example.com:8080/api/v1", "https", "8080", "/api/v1"},
		{"http://localhost:3000/test", "http", "3000", "/test"},
		// IPv6 addresses
		{"https://[::1]:8080/path", "https", "8080", "/path"},
		{"https://[::1]/path", "https", "", "/path"},
		{"https://[2001:db8::1]:443/api", "https", "443", "/api"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			protocol, port, path := extractURIComponents(tt.uri)
			if protocol != tt.protocol {
				t.Errorf("protocol = '%s', want '%s'", protocol, tt.protocol)
			}
			if port != tt.port {
				t.Errorf("port = '%s', want '%s'", port, tt.port)
			}
			if path != tt.path {
				t.Errorf("path = '%s', want '%s'", path, tt.path)
			}
		})
	}
}

// Helper function for creating string pointers
func strPtr(s string) *string {
	return &s
}

func TestExtractDomain_IPv6(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		// IPv6 addresses
		{"https://[::1]:8080/path", "[::1]"},
		{"http://[::1]/api", "[::1]"},
		{"https://[2001:db8::1]:443/api", "[2001:db8::1]"},
		{"https://[fe80::1%eth0]:8080", "[fe80::1%eth0]"},
		{"[::1]:8080", "[::1]"},
		{"[::1]", "[::1]"},
		// Regular domains (ensure IPv6 fix doesn't break these)
		{"https://example.com:8080/path", "example.com"},
		{"http://example.com", "example.com"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			got := extractDomain(tt.uri)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}

func TestBuildURIFromAttributes_ServiceWithComponents(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]string
		want  string
	}{
		{
			name:  "service with scheme is used as-is",
			attrs: map[string]string{"service": "https://example.com/existing"},
			want:  "https://example.com/existing",
		},
		{
			name:  "service without scheme gets protocol/port/path applied",
			attrs: map[string]string{"service": "example.com", "protocol": "http", "port": "8080", "path": "/api"},
			want:  "http://example.com:8080/api",
		},
		{
			name:  "service without scheme defaults to https",
			attrs: map[string]string{"service": "example.com"},
			want:  "https://example.com",
		},
		{
			name:  "service with port only",
			attrs: map[string]string{"service": "example.com", "port": "3000"},
			want:  "https://example.com:3000",
		},
		{
			name:  "service with path only",
			attrs: map[string]string{"service": "example.com", "path": "api/v1"},
			want:  "https://example.com/api/v1",
		},
		{
			name:  "service with path starting with slash",
			attrs: map[string]string{"service": "example.com", "path": "/api/v1"},
			want:  "https://example.com/api/v1",
		},
		{
			name:  "domain with protocol/port/path",
			attrs: map[string]string{"domain": "example.com", "protocol": "http", "port": "8080", "path": "/api"},
			want:  "http://example.com:8080/api",
		},
		{
			name:  "empty attrs returns empty",
			attrs: map[string]string{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildURIFromAttributes(tt.attrs)
			if got != tt.want {
				t.Errorf("BuildURIFromAttributes(%v) = %q, want %q", tt.attrs, got, tt.want)
			}
		})
	}
}
