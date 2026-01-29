package ssh

import (
	"testing"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

// Test SSH key in OpenSSH format (ED25519)
const testED25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBHK9tokyHaTp5mBq8HVJvpUTsJpBkGnP6uJhaaPQf8PQAAAJjcSq3r3Eqt
6wAAAAtzc2gtZWQyNTUxOQAAACBHK9tokyHaTp5mBq8HVJvpUTsJpBkGnP6uJhaaPQf8PQ
AAAEALgFRQf9K+T4FPh6z8TlUlPZJJpZcVkT8mzG8GJ4VxqEcr22iTIdpOnmYGrwdUm+lR
OwmkGQac/q4mFpo9B/w9AAAADnRlc3RAYml0d2FyZGVuAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----`

const testED25519PublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEcr22iTIdpOnmYGrwdUm+lROwmkGQac/q4mFpo9B/w9 test@bitwarden`

func TestIsSSHKeyItem(t *testing.T) {
	tests := []struct {
		name string
		item *bitwarden.Item
		want bool
	}{
		{
			name: "nil item",
			item: nil,
			want: false,
		},
		{
			name: "login item",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeLogin,
			},
			want: false,
		},
		{
			name: "ssh key item without SSHKey data",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeSSHKey,
			},
			want: false,
		},
		{
			name: "valid ssh key item",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeSSHKey,
				SSHKey: &bitwarden.SSHKey{
					PrivateKey:     testED25519PrivateKey,
					PublicKey:      testED25519PublicKey,
					KeyFingerprint: "SHA256:test",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSSHKeyItem(tt.item)
			if got != tt.want {
				t.Errorf("IsSSHKeyItem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSSHKey(t *testing.T) {
	tests := []struct {
		name    string
		item    *bitwarden.Item
		wantErr bool
	}{
		{
			name:    "nil item",
			item:    nil,
			wantErr: true,
		},
		{
			name: "not an SSH key item",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeLogin,
			},
			wantErr: true,
		},
		{
			name: "empty private key",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeSSHKey,
				SSHKey: &bitwarden.SSHKey{
					PrivateKey: "",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid private key format",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeSSHKey,
				SSHKey: &bitwarden.SSHKey{
					PrivateKey: "not a valid key",
				},
			},
			wantErr: true,
		},
		{
			name: "valid ED25519 key",
			item: &bitwarden.Item{
				Type: bitwarden.ItemTypeSSHKey,
				SSHKey: &bitwarden.SSHKey{
					PrivateKey:     testED25519PrivateKey,
					PublicKey:      testED25519PublicKey,
					KeyFingerprint: "SHA256:test",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := ParseSSHKey(tt.item)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSSHKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && signer == nil {
				t.Errorf("ParseSSHKey() returned nil signer without error")
			}
		})
	}
}

func TestParseSSHKey_KeyType(t *testing.T) {
	item := &bitwarden.Item{
		Type: bitwarden.ItemTypeSSHKey,
		SSHKey: &bitwarden.SSHKey{
			PrivateKey:     testED25519PrivateKey,
			PublicKey:      testED25519PublicKey,
			KeyFingerprint: "SHA256:test",
		},
	}

	signer, err := ParseSSHKey(item)
	if err != nil {
		t.Fatalf("ParseSSHKey() error = %v", err)
	}

	pubKey := signer.PublicKey()
	if pubKey.Type() != "ssh-ed25519" {
		t.Errorf("ParseSSHKey() key type = %v, want ssh-ed25519", pubKey.Type())
	}
}

func TestFindSSHKeyByPublicKey(t *testing.T) {
	item := &bitwarden.Item{
		ID:   "test-id",
		Name: "test-key",
		Type: bitwarden.ItemTypeSSHKey,
		SSHKey: &bitwarden.SSHKey{
			PrivateKey:     testED25519PrivateKey,
			PublicKey:      testED25519PublicKey,
			KeyFingerprint: "SHA256:test",
		},
	}

	signer, err := ParseSSHKey(item)
	if err != nil {
		t.Fatalf("ParseSSHKey() error = %v", err)
	}

	keys := []*SSHKeyItem{
		{
			Item:   item,
			Signer: signer,
		},
	}

	// Test finding by matching public key
	found, ok := FindSSHKeyByPublicKey(keys, signer.PublicKey())
	if !ok {
		t.Error("FindSSHKeyByPublicKey() should find matching key")
	}
	if found.Item.ID != "test-id" {
		t.Errorf("FindSSHKeyByPublicKey() found wrong key, got ID = %v", found.Item.ID)
	}

	// Test with empty keys list
	_, ok = FindSSHKeyByPublicKey([]*SSHKeyItem{}, signer.PublicKey())
	if ok {
		t.Error("FindSSHKeyByPublicKey() should not find key in empty list")
	}
}
