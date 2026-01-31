package dbus

import (
	"errors"
	"testing"

	"github.com/joe/bitwarden-keyring/internal/bitwarden"
)

func TestToDBusError_IsLocked(t *testing.T) {
	err := toDBusError(bitwarden.ErrVaultLocked)

	if err == nil {
		t.Fatal("toDBusError(ErrVaultLocked) returned nil")
	}

	// Should map to the IsLocked error name
	if err.Name != ErrIsLocked {
		t.Errorf("error name = %q, want %q", err.Name, ErrIsLocked)
	}
}

func TestToDBusError_UserCancelled(t *testing.T) {
	err := toDBusError(bitwarden.ErrUserCancelled)

	if err == nil {
		t.Fatal("toDBusError(ErrUserCancelled) returned nil")
	}

	// Should map to the prompt dismissed error (from spec)
	const promptDismissedError = "org.freedesktop.Secret.Error.PromptDismissed"
	if err.Name != promptDismissedError {
		t.Errorf("error name = %q, want %q", err.Name, promptDismissedError)
	}
}

func TestToDBusError_DefaultError(t *testing.T) {
	customErr := errors.New("some other error")
	err := toDBusError(customErr)

	if err == nil {
		t.Fatal("toDBusError(customErr) returned nil")
	}

	// Should return a generic "backend error" message
	if len(err.Body) == 0 {
		t.Error("error body is empty")
	}

	// Should not contain the original error message in name
	if err.Name == "" {
		t.Error("error name is empty")
	}
}

func TestToDBusError_Nil(t *testing.T) {
	// Nil error should return nil
	err := toDBusError(nil)
	if err != nil {
		t.Errorf("toDBusError(nil) = %v, want nil", err)
	}
}

func TestToDBusError_APIError(t *testing.T) {
	apiErr := &bitwarden.APIError{
		StatusCode: 401,
		Path:       "/unlock",
	}

	err := toDBusError(apiErr)

	if err == nil {
		t.Fatal("toDBusError(APIError) returned nil")
	}

	// Should return a generic backend error, not the original error
	if err.Name == "" {
		t.Error("error name is empty")
	}

	// Body should not contain sensitive info
	if len(err.Body) > 0 {
		if errMsg, ok := err.Body[0].(string); ok {
			if errMsg != "backend error" {
				t.Errorf("error message = %q, want %q", errMsg, "backend error")
			}
		}
	}
}
