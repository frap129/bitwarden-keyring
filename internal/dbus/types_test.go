package dbus

import (
	"testing"
)

func TestSanitizeUnsanitizeID_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		uuid string
	}{
		{
			name: "standard UUID with hyphens",
			uuid: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name: "UUID with underscores",
			uuid: "550e8400_e29b_41d4_a716_446655440000",
		},
		{
			name: "already sanitized (no hyphens)",
			uuid: "550e8400e29b41d4a716446655440000",
		},
		{
			name: "mixed hyphens and underscores",
			uuid: "550e8400-e29b_41d4-a716_446655440000",
		},
		{
			name: "another standard UUID",
			uuid: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Sanitize the ID (removes hyphens)
			sanitized := SanitizeID(tt.uuid)

			// Unsanitize should restore hyphens in correct positions for 32-char hex
			// But note: SanitizeID only removes hyphens, not underscores
			// So if original has underscores, they will remain
			unsanitized := UnsanitizeID(sanitized)

			// For UUIDs without underscores, round-trip should work
			// Sanitize removes hyphens, Unsanitize adds them back
			// The key test: sanitizing a sanitized string should be idempotent
			resanitized := SanitizeID(sanitized)
			if resanitized != sanitized {
				t.Errorf("SanitizeID is not idempotent: %q -> %q -> %q", tt.uuid, sanitized, resanitized)
			}

			// For standard UUID format (with hyphens), verify round-trip
			if len(tt.uuid) == 36 && tt.uuid[8] == '-' && tt.uuid[13] == '-' {
				if unsanitized != tt.uuid {
					t.Errorf("round-trip failed: %q -> %q -> %q", tt.uuid, sanitized, unsanitized)
				}
			}
		})
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard UUID",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400e29b41d4a716446655440000",
		},
		{
			name:     "already sanitized",
			input:    "550e8400e29b41d4a716446655440000",
			expected: "550e8400e29b41d4a716446655440000",
		},
		{
			name:     "multiple hyphens",
			input:    "a-b-c-d-e",
			expected: "abcde",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no hyphens",
			input:    "abcdef",
			expected: "abcdef",
		},
		{
			name:     "only hyphens",
			input:    "----",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeID(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestUnsanitizeID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "32 character hex string",
			input:    "550e8400e29b41d4a716446655440000",
			expected: "550e8400-e29b-41d4-a716-446655440000",
		},
		{
			name:     "not 32 characters - returned as-is",
			input:    "550e8400e29b41d4",
			expected: "550e8400e29b41d4",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "longer than 32 chars",
			input:    "550e8400e29b41d4a71644665544000000",
			expected: "550e8400e29b41d4a71644665544000000",
		},
		{
			name:     "31 characters",
			input:    "550e8400e29b41d4a71644665544000",
			expected: "550e8400e29b41d4a71644665544000",
		},
		{
			name:     "with existing hyphens",
			input:    "550e8400-e29b-41d4-a716-446655440000",
			expected: "550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnsanitizeID(tt.input)
			if got != tt.expected {
				t.Errorf("UnsanitizeID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify D-Bus constants are defined
	tests := []struct {
		name  string
		value string
	}{
		{"BusName", BusName},
		{"ServicePath", string(ServicePath)},
		{"SessionPath", SessionPath},
		{"CollectionPath", CollectionPath},
		{"PromptPath", PromptPath},
		{"AliasPath", AliasPath},
		{"ServiceInterface", ServiceInterface},
		{"CollectionInterface", CollectionInterface},
		{"ItemInterface", ItemInterface},
		{"SessionInterface", SessionInterface},
		{"PromptInterface", PromptInterface},
		{"PropertiesInterface", PropertiesInterface},
		{"ErrIsLocked", ErrIsLocked},
		{"ErrNoSession", ErrNoSession},
		{"ErrNoSuchObject", ErrNoSuchObject},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value == "" {
				t.Errorf("%s is empty", tt.name)
			}
		})
	}

	// Verify DefaultCollectionPath
	if string(DefaultCollectionPath) != CollectionPath+"default" {
		t.Errorf("DefaultCollectionPath = %q, want %q", DefaultCollectionPath, CollectionPath+"default")
	}

	// Verify NoPrompt path
	if string(NoPrompt) != "/" {
		t.Errorf("NoPrompt = %q, want %q", NoPrompt, "/")
	}
}
