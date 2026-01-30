package bitwarden

import (
	"errors"
	"time"
)

// Common errors
var (
	ErrVaultLocked = errors.New("vault is locked")
)

// ItemType represents the type of Bitwarden vault item
type ItemType int

const (
	ItemTypeLogin      ItemType = 1
	ItemTypeSecureNote ItemType = 2
	ItemTypeCard       ItemType = 3
	ItemTypeIdentity   ItemType = 4
	ItemTypeSSHKey     ItemType = 5
)

// Item represents a Bitwarden vault item
type Item struct {
	ID             string      `json:"id"`
	OrganizationID *string     `json:"organizationId"`
	FolderID       *string     `json:"folderId"`
	Type           ItemType    `json:"type"`
	Name           string      `json:"name"`
	Notes          *string     `json:"notes"`
	Favorite       bool        `json:"favorite"`
	Login          *Login      `json:"login,omitempty"`
	SecureNote     *SecureNote `json:"secureNote,omitempty"`
	Card           *Card       `json:"card,omitempty"`
	Identity       *Identity   `json:"identity,omitempty"`
	SSHKey         *SSHKey     `json:"sshKey,omitempty"`
	Fields         []Field     `json:"fields,omitempty"`
	Reprompt       int         `json:"reprompt"`
	RevisionDate   time.Time   `json:"revisionDate"`
	CreationDate   time.Time   `json:"creationDate"`
	DeletedDate    *time.Time  `json:"deletedDate,omitempty"`
}

// Login represents login credentials in a Bitwarden item
type Login struct {
	URIs     []URI   `json:"uris,omitempty"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	TOTP     *string `json:"totp,omitempty"`
}

// URI represents a URI associated with a login item
type URI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match,omitempty"`
}

// SecureNote represents a secure note item
type SecureNote struct {
	Type int `json:"type"`
}

// Card represents a payment card item
type Card struct {
	CardholderName *string `json:"cardholderName"`
	Brand          *string `json:"brand"`
	Number         *string `json:"number"`
	ExpMonth       *string `json:"expMonth"`
	ExpYear        *string `json:"expYear"`
	Code           *string `json:"code"`
}

// Identity represents an identity item
type Identity struct {
	Title      *string `json:"title"`
	FirstName  *string `json:"firstName"`
	MiddleName *string `json:"middleName"`
	LastName   *string `json:"lastName"`
	Email      *string `json:"email"`
	Phone      *string `json:"phone"`
	Company    *string `json:"company"`
}

// SSHKey represents an SSH key item
type SSHKey struct {
	PrivateKey     string `json:"privateKey"`     // OpenSSH or PKCS#8 format
	PublicKey      string `json:"publicKey"`      // OpenSSH format
	KeyFingerprint string `json:"keyFingerprint"` // SHA256 fingerprint
}

// Field represents a custom field on an item
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  int    `json:"type"` // 0=text, 1=hidden, 2=boolean
}

// Folder represents a Bitwarden folder
type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// APIResponse wraps Bitwarden API responses
type APIResponse[T any] struct {
	Success bool    `json:"success"`
	Data    T       `json:"data"`
	Message *string `json:"message,omitempty"`
}

// ListResponse wraps list responses from Bitwarden API
type ListResponse[T any] struct {
	Success bool `json:"success"`
	Data    struct {
		Data []T `json:"data"`
	} `json:"data"`
	Message *string `json:"message,omitempty"`
}

// UnlockRequest represents a request to unlock the vault
type UnlockRequest struct {
	Password string `json:"password"`
}

// UnlockResponse represents the response from unlocking the vault
type UnlockResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Title   string `json:"title"`
		Message string `json:"message"`
		Raw     string `json:"raw"` // Session key
	} `json:"data"`
}

// StatusResponse represents the vault status
type StatusResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Template struct {
			ServerURL *string `json:"serverUrl"`
			LastSync  *string `json:"lastSync"`
			UserEmail *string `json:"userEmail"`
			UserID    *string `json:"userId"`
			Status    string  `json:"status"` // "locked", "unlocked", "unauthenticated"
		} `json:"template"`
	} `json:"data"`
}

// CreateItemRequest represents a request to create a new item
type CreateItemRequest struct {
	OrganizationID *string  `json:"organizationId,omitempty"`
	FolderID       *string  `json:"folderId,omitempty"`
	Type           ItemType `json:"type"`
	Name           string   `json:"name"`
	Notes          *string  `json:"notes,omitempty"`
	Favorite       bool     `json:"favorite"`
	Login          *Login   `json:"login,omitempty"`
	SSHKey         *SSHKey  `json:"sshKey,omitempty"`
	Fields         []Field  `json:"fields,omitempty"`
	Reprompt       int      `json:"reprompt"`
}

// ToUpdateRequest creates a CreateItemRequest from an existing Item,
// preserving all fields for updates. This ensures that non-omitempty fields
// like Favorite and Reprompt are not silently zeroed during updates.
func (i *Item) ToUpdateRequest() CreateItemRequest {
	return CreateItemRequest{
		OrganizationID: i.OrganizationID,
		FolderID:       i.FolderID,
		Type:           i.Type,
		Name:           i.Name,
		Notes:          i.Notes,
		Favorite:       i.Favorite,
		Login:          i.Login,
		SSHKey:         i.SSHKey,
		Fields:         i.Fields,
		Reprompt:       i.Reprompt,
	}
}
