package dbus

import (
	"testing"

	"github.com/joe/bitwarden-keyring/internal/mapping"
)

func TestHasMeaningfulAttrs(t *testing.T) {
	tests := []struct {
		name     string
		attrs    map[string]string
		expected bool
	}{
		{
			name:     "empty map",
			attrs:    map[string]string{},
			expected: false,
		},
		{
			name:     "nil map",
			attrs:    nil,
			expected: false,
		},
		{
			name:     "only xdg:schema",
			attrs:    map[string]string{"xdg:schema": "org.gnome.Secret.Storage"},
			expected: false,
		},
		{
			name:     "xdg:schema with empty value",
			attrs:    map[string]string{"xdg:schema": ""},
			expected: false,
		},
		{
			name:     "label attribute",
			attrs:    map[string]string{"label": "My Password"},
			expected: true,
		},
		{
			name:     "service attribute",
			attrs:    map[string]string{"service": "github.com"},
			expected: true,
		},
		{
			name:     "domain attribute",
			attrs:    map[string]string{"domain": "example.com"},
			expected: true,
		},
		{
			name:     "server attribute",
			attrs:    map[string]string{"server": "smtp.gmail.com"},
			expected: true,
		},
		{
			name:     "username attribute",
			attrs:    map[string]string{"username": "john"},
			expected: true,
		},
		{
			name:     "user attribute",
			attrs:    map[string]string{"user": "jane"},
			expected: true,
		},
		{
			name:     "mapping.AttrService",
			attrs:    map[string]string{mapping.AttrService: "myapp"},
			expected: true,
		},
		{
			name:     "mapping.AttrUsername",
			attrs:    map[string]string{mapping.AttrUsername: "admin"},
			expected: true,
		},
		{
			name:     "mapping.AttrDomain",
			attrs:    map[string]string{mapping.AttrDomain: "company.net"},
			expected: true,
		},
		{
			name:     "mapping.AttrServer",
			attrs:    map[string]string{mapping.AttrServer: "db.local"},
			expected: true,
		},
		{
			name:     "xdg:schema with label",
			attrs:    map[string]string{"xdg:schema": "org.gnome.Secret.Storage", "label": "Important"},
			expected: true,
		},
		{
			name:     "multiple meaningful attrs",
			attrs:    map[string]string{"service": "aws", "username": "root", "domain": "amazon.com"},
			expected: true,
		},
		{
			name:     "label with empty value",
			attrs:    map[string]string{"label": ""},
			expected: false,
		},
		{
			name:     "service with empty value",
			attrs:    map[string]string{"service": ""},
			expected: false,
		},
		{
			name:     "unrelated attributes only",
			attrs:    map[string]string{"foo": "bar", "baz": "qux"},
			expected: false,
		},
		{
			name:     "mixed meaningful and meaningless",
			attrs:    map[string]string{"foo": "bar", "username": "admin"},
			expected: true,
		},
		{
			name:     "case sensitive - LABEL not recognized",
			attrs:    map[string]string{"LABEL": "Test"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasMeaningfulAttrs(tt.attrs)
			if got != tt.expected {
				t.Errorf("hasMeaningfulAttrs(%v) = %v, want %v", tt.attrs, got, tt.expected)
			}
		})
	}
}

func TestHasMeaningfulAttrs_AllIdentityKeys(t *testing.T) {
	// Test all known identity keys
	identityKeys := []string{
		"label",
		"service",
		"domain",
		"server",
		"username",
		"user",
		mapping.AttrService,
		mapping.AttrUsername,
		mapping.AttrDomain,
		mapping.AttrServer,
	}

	for _, key := range identityKeys {
		t.Run("key:"+key, func(t *testing.T) {
			attrs := map[string]string{key: "somevalue"}
			if !hasMeaningfulAttrs(attrs) {
				t.Errorf("hasMeaningfulAttrs should return true for key %q", key)
			}
		})
	}
}
