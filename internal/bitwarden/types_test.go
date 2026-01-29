package bitwarden

import (
	"testing"
	"time"
)

func TestItem_ToUpdateRequest_PreservesFields(t *testing.T) {
	orgID := "org-123"
	folderID := "folder-456"
	notes := "some notes"
	username := "testuser"
	password := "secret123"

	item := &Item{
		ID:             "item-id",
		OrganizationID: &orgID,
		FolderID:       &folderID,
		Type:           ItemTypeLogin,
		Name:           "Test Item",
		Notes:          &notes,
		Favorite:       true,
		Reprompt:       1,
		Login: &Login{
			Username: &username,
			Password: &password,
			URIs:     []URI{{URI: "https://example.com"}},
		},
		Fields: []Field{
			{Name: "custom", Value: "value", Type: 0},
		},
		RevisionDate: time.Now(),
		CreationDate: time.Now().Add(-24 * time.Hour),
	}

	req := item.ToUpdateRequest()

	// Verify all fields are preserved
	if req.OrganizationID == nil || *req.OrganizationID != orgID {
		t.Errorf("OrganizationID not preserved: got %v, want %s", req.OrganizationID, orgID)
	}
	if req.FolderID == nil || *req.FolderID != folderID {
		t.Errorf("FolderID not preserved: got %v, want %s", req.FolderID, folderID)
	}
	if req.Type != ItemTypeLogin {
		t.Errorf("Type not preserved: got %v, want %v", req.Type, ItemTypeLogin)
	}
	if req.Name != "Test Item" {
		t.Errorf("Name not preserved: got %s, want 'Test Item'", req.Name)
	}
	if req.Notes == nil || *req.Notes != notes {
		t.Errorf("Notes not preserved: got %v, want %s", req.Notes, notes)
	}
	if req.Favorite != true {
		t.Errorf("Favorite not preserved: got %v, want true", req.Favorite)
	}
	if req.Reprompt != 1 {
		t.Errorf("Reprompt not preserved: got %d, want 1", req.Reprompt)
	}
	if req.Login == nil {
		t.Error("Login not preserved: got nil")
	} else {
		if req.Login.Username == nil || *req.Login.Username != username {
			t.Errorf("Login.Username not preserved: got %v, want %s", req.Login.Username, username)
		}
		if req.Login.Password == nil || *req.Login.Password != password {
			t.Errorf("Login.Password not preserved: got %v, want %s", req.Login.Password, password)
		}
		if len(req.Login.URIs) != 1 || req.Login.URIs[0].URI != "https://example.com" {
			t.Errorf("Login.URIs not preserved: got %v", req.Login.URIs)
		}
	}
	if len(req.Fields) != 1 || req.Fields[0].Name != "custom" {
		t.Errorf("Fields not preserved: got %v", req.Fields)
	}
}

func TestItem_ToUpdateRequest_HandlesNilFields(t *testing.T) {
	item := &Item{
		ID:       "item-id",
		Type:     ItemTypeLogin,
		Name:     "Minimal Item",
		Favorite: false,
		Reprompt: 0,
	}

	req := item.ToUpdateRequest()

	if req.OrganizationID != nil {
		t.Errorf("OrganizationID should be nil: got %v", req.OrganizationID)
	}
	if req.FolderID != nil {
		t.Errorf("FolderID should be nil: got %v", req.FolderID)
	}
	if req.Notes != nil {
		t.Errorf("Notes should be nil: got %v", req.Notes)
	}
	if req.Login != nil {
		t.Errorf("Login should be nil: got %v", req.Login)
	}
	if req.Fields != nil {
		t.Errorf("Fields should be nil: got %v", req.Fields)
	}
	if req.Name != "Minimal Item" {
		t.Errorf("Name not preserved: got %s", req.Name)
	}
}

func TestItem_ToUpdateRequest_PreservesSSHKey(t *testing.T) {
	item := &Item{
		ID:       "ssh-item-id",
		Type:     ItemTypeSSHKey,
		Name:     "My SSH Key",
		Favorite: true,
		Reprompt: 0,
		SSHKey: &SSHKey{
			PrivateKey:     "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
			PublicKey:      "ssh-ed25519 AAAA... comment",
			KeyFingerprint: "SHA256:abcdefgh",
		},
	}

	req := item.ToUpdateRequest()

	// Verify SSH key fields are preserved
	if req.Type != ItemTypeSSHKey {
		t.Errorf("Type not preserved: got %v, want %v", req.Type, ItemTypeSSHKey)
	}
	if req.Name != "My SSH Key" {
		t.Errorf("Name not preserved: got %s, want 'My SSH Key'", req.Name)
	}
	if req.Favorite != true {
		t.Errorf("Favorite not preserved: got %v, want true", req.Favorite)
	}
	if req.SSHKey == nil {
		t.Fatal("SSHKey not preserved: got nil")
	}
	if req.SSHKey.PrivateKey != item.SSHKey.PrivateKey {
		t.Errorf("SSHKey.PrivateKey not preserved: got %s", req.SSHKey.PrivateKey)
	}
	if req.SSHKey.PublicKey != item.SSHKey.PublicKey {
		t.Errorf("SSHKey.PublicKey not preserved: got %s", req.SSHKey.PublicKey)
	}
	if req.SSHKey.KeyFingerprint != item.SSHKey.KeyFingerprint {
		t.Errorf("SSHKey.KeyFingerprint not preserved: got %s", req.SSHKey.KeyFingerprint)
	}

	// Verify Login is nil for SSH key items
	if req.Login != nil {
		t.Errorf("Login should be nil for SSH key items: got %v", req.Login)
	}
}
