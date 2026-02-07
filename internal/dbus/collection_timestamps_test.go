package dbus

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// testBWClient creates a bitwarden client pointing at the test server
func testBWClient(t *testing.T, server *httptest.Server) *bitwarden.Client {
	t.Helper()
	// Parse port from server URL
	port := server.Listener.Addr().(*net.TCPAddr).Port
	return bitwarden.NewClient(port)
}

func TestCollection_lastSyncUnix_ValidTimestamp(t *testing.T) {
	expectedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	lastSyncValue := expectedTime.Format(time.RFC3339Nano)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		resp := map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"template": map[string]interface{}{
					"lastSync": lastSyncValue,
					"status":   "unlocked",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	// Create client with test server
	client := testBWClient(t, ts)

	coll := &Collection{
		bwClient: client,
		label:    "Test",
	}

	got := coll.lastSyncUnix(context.Background())
	want := expectedTime.Unix()

	if got != want {
		t.Errorf("lastSyncUnix() = %d, want %d", got, want)
	}
}

func TestCollection_lastSyncUnix_UsingRFC3339(t *testing.T) {
	expectedTime := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	lastSyncValue := expectedTime.Format(time.RFC3339)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"template": map[string]interface{}{
					"lastSync": lastSyncValue,
					"status":   "unlocked",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := testBWClient(t, ts)
	coll := &Collection{
		bwClient: client,
		label:    "Test",
	}

	got := coll.lastSyncUnix(context.Background())
	want := expectedTime.Unix()

	if got != want {
		t.Errorf("lastSyncUnix() = %d, want %d", got, want)
	}
}

func TestCollection_lastSyncUnix_EmptyLastSync(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"template": map[string]interface{}{
					"lastSync": "",
					"status":   "unlocked",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := testBWClient(t, ts)
	coll := &Collection{
		bwClient: client,
		label:    "Test",
	}

	got := coll.lastSyncUnix(context.Background())

	if got != 0 {
		t.Errorf("lastSyncUnix() = %d, want 0 for empty lastSync", got)
	}
}

func TestCollection_lastSyncUnix_MissingLastSync(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"template": map[string]interface{}{
					"status": "unlocked",
					// No lastSync field
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := testBWClient(t, ts)
	coll := &Collection{
		bwClient: client,
		label:    "Test",
	}

	got := coll.lastSyncUnix(context.Background())

	if got != 0 {
		t.Errorf("lastSyncUnix() = %d, want 0 for missing lastSync", got)
	}
}

func TestCollection_lastSyncUnix_MalformedDate(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success": true,
			"data": map[string]interface{}{
				"template": map[string]interface{}{
					"lastSync": "not-a-valid-date",
					"status":   "unlocked",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := testBWClient(t, ts)
	coll := &Collection{
		bwClient: client,
		label:    "Test",
	}

	got := coll.lastSyncUnix(context.Background())

	if got != 0 {
		t.Errorf("lastSyncUnix() = %d, want 0 for malformed date", got)
	}
}

func TestCollection_lastSyncUnix_StatusError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "internal error",
		})
	}))
	defer ts.Close()

	client := testBWClient(t, ts)
	coll := &Collection{
		bwClient: client,
		label:    "Test",
	}

	got := coll.lastSyncUnix(context.Background())

	if got != 0 {
		t.Errorf("lastSyncUnix() = %d, want 0 when Status fails", got)
	}
}

func TestCollection_Get_CreatedModified(t *testing.T) {
	expectedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	lastSyncValue := expectedTime.Format(time.RFC3339Nano)
	expectedUnix := uint64(expectedTime.Unix())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			resp := map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"template": map[string]interface{}{
						"lastSync": lastSyncValue,
						"status":   "unlocked",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case "/list":
			// Return empty list for Items property
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    []interface{}{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := testBWClient(t, ts)

	// Create a minimal collection
	coll := &Collection{
		bwClient: client,
		label:    "Test",
		path:     "/org/freedesktop/secrets/collection/test",
	}

	tests := []struct {
		name     string
		property string
	}{
		{"Created", "Created"},
		{"Modified", "Modified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variant, dbusErr := coll.Get(CollectionInterface, tt.property)
			if dbusErr != nil {
				t.Fatalf("Get(%s) returned error: %v", tt.property, dbusErr)
			}

			got, ok := variant.Value().(uint64)
			if !ok {
				t.Fatalf("Get(%s) returned non-uint64: %T", tt.property, variant.Value())
			}

			if got != expectedUnix {
				t.Errorf("Get(%s) = %d, want %d", tt.property, got, expectedUnix)
			}
		})
	}
}

func TestCollection_GetAll_Timestamps(t *testing.T) {
	expectedTime := time.Date(2024, 3, 20, 15, 45, 30, 0, time.UTC)
	lastSyncValue := expectedTime.Format(time.RFC3339Nano)
	expectedUnix := uint64(expectedTime.Unix())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			resp := map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"template": map[string]interface{}{
						"lastSync": lastSyncValue,
						"status":   "unlocked",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		case "/list":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    []interface{}{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := testBWClient(t, ts)

	coll := &Collection{
		bwClient: client,
		label:    "Test",
		path:     "/org/freedesktop/secrets/collection/test",
	}

	props, dbusErr := coll.GetAll(CollectionInterface)
	if dbusErr != nil {
		t.Fatalf("GetAll() returned error: %v", dbusErr)
	}

	// Check Created
	createdVariant, ok := props["Created"]
	if !ok {
		t.Fatal("GetAll() missing Created property")
	}
	created, ok := createdVariant.Value().(uint64)
	if !ok {
		t.Fatalf("Created is not uint64: %T", createdVariant.Value())
	}
	if created != expectedUnix {
		t.Errorf("Created = %d, want %d", created, expectedUnix)
	}

	// Check Modified
	modifiedVariant, ok := props["Modified"]
	if !ok {
		t.Fatal("GetAll() missing Modified property")
	}
	modified, ok := modifiedVariant.Value().(uint64)
	if !ok {
		t.Fatalf("Modified is not uint64: %T", modifiedVariant.Value())
	}
	if modified != expectedUnix {
		t.Errorf("Modified = %d, want %d", modified, expectedUnix)
	}

	// Created and Modified should be equal
	if created != modified {
		t.Errorf("Created (%d) != Modified (%d)", created, modified)
	}
}

func TestCollection_GetAll_ZeroOnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			// Return error for status endpoint
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "status unavailable",
			})
		case "/list":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"data":    []interface{}{},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := testBWClient(t, ts)

	coll := &Collection{
		bwClient: client,
		label:    "Test",
		path:     "/org/freedesktop/secrets/collection/test",
	}

	props, dbusErr := coll.GetAll(CollectionInterface)
	if dbusErr != nil {
		t.Fatalf("GetAll() returned error: %v", dbusErr)
	}

	created, _ := props["Created"].Value().(uint64)
	modified, _ := props["Modified"].Value().(uint64)

	if created != 0 {
		t.Errorf("Created = %d, want 0 on error", created)
	}
	if modified != 0 {
		t.Errorf("Modified = %d, want 0 on error", modified)
	}
}
