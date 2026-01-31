package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x42}},
		{"15 bytes", bytes.Repeat([]byte{0xAA}, 15)},
		{"16 bytes", bytes.Repeat([]byte{0xBB}, 16)},
		{"17 bytes", bytes.Repeat([]byte{0xCC}, 17)},
		{"32 bytes", bytes.Repeat([]byte{0xDD}, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key
			key := bytes.Repeat([]byte{0x11}, AESKeyBytes)

			// Encrypt
			ciphertext, iv, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Verify ciphertext is not empty (unless plaintext is empty, we still get padded block)
			if len(ciphertext) == 0 {
				t.Error("ciphertext is empty")
			}

			// Verify IV is correct size
			if len(iv) != AESBlockBytes {
				t.Errorf("IV size = %d, want %d", len(iv), AESBlockBytes)
			}

			// Verify ciphertext is multiple of block size
			if len(ciphertext)%AESBlockBytes != 0 {
				t.Errorf("ciphertext size %d is not multiple of block size %d", len(ciphertext), AESBlockBytes)
			}

			// Decrypt
			decrypted, err := Decrypt(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify roundtrip
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("roundtrip failed: got %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestPKCS7UnpadFullBlockPadding(t *testing.T) {
	// When plaintext is multiple of block size (e.g., 16 bytes),
	// PKCS7 adds a full block of padding (16 bytes of 0x10).
	// pkcs7Unpad should handle this and return plaintext with full block removed.

	plaintext := bytes.Repeat([]byte{0x42}, 16) // 16 bytes
	key := bytes.Repeat([]byte{0x11}, AESKeyBytes)

	// Encrypt will add full block padding
	ciphertext, iv, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Ciphertext should be 32 bytes (16 original + 16 padding)
	if len(ciphertext) != 32 {
		t.Errorf("ciphertext size = %d, want 32", len(ciphertext))
	}

	// Decrypt and verify
	decrypted, err := Decrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("got %v, want %v", decrypted, plaintext)
	}
}

func TestPKCS7UnpadEmpty(t *testing.T) {
	// Empty plaintext should be padded to 16 bytes (all 0x10),
	// then after decryption, should return empty.
	plaintext := []byte{}
	key := bytes.Repeat([]byte{0x11}, AESKeyBytes)

	ciphertext, iv, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("empty plaintext roundtrip: got %d bytes, want 0", len(decrypted))
	}
}

func TestPKCS7UnpadInvalidPaddingLastByteZero(t *testing.T) {
	// Test pkcs7Unpad with last byte = 0 (invalid)
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00}

	_, err := pkcs7Unpad(data, AESBlockBytes)
	if err == nil {
		t.Error("pkcs7Unpad should reject last byte = 0")
	}
}

func TestPKCS7UnpadInvalidPaddingTooLarge(t *testing.T) {
	// Test pkcs7Unpad with last byte > blockSize (invalid)
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x20} // 0x20 = 32, > 16

	_, err := pkcs7Unpad(data, AESBlockBytes)
	if err == nil {
		t.Error("pkcs7Unpad should reject padding > blockSize")
	}
}

func TestPKCS7UnpadInvalidPaddingInconsistent(t *testing.T) {
	// Test pkcs7Unpad with inconsistent padding bytes
	// Last byte says 3 bytes of padding, but only first is correct
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x03, 0xFF, 0x03} // Last 3 should be [0x03, 0x03, 0x03]

	_, err := pkcs7Unpad(data, AESBlockBytes)
	if err == nil {
		t.Error("pkcs7Unpad should reject inconsistent padding")
	}
}

func TestPKCS7PadDoesNotMutateCaller(t *testing.T) {
	// Verify that pkcs7Pad allocates and copies, doesn't mutate the input
	original := []byte{0x42, 0x43, 0x44}
	originalCopy := make([]byte, len(original))
	copy(originalCopy, original)

	padded := pkcs7Pad(original, AESBlockBytes)

	// Original should be unchanged
	if !bytes.Equal(original, originalCopy) {
		t.Errorf("pkcs7Pad mutated the input: %v != %v", original, originalCopy)
	}

	// Padded should be longer
	if len(padded) != AESBlockBytes {
		t.Errorf("padded size = %d, want %d", len(padded), AESBlockBytes)
	}

	// First 3 bytes should match original
	if !bytes.Equal(padded[:3], original) {
		t.Errorf("padded prefix mismatch")
	}

	// Remaining should be padding (0x0D = 13)
	expectedPadding := byte(AESBlockBytes - len(original))
	for i := len(original); i < len(padded); i++ {
		if padded[i] != expectedPadding {
			t.Errorf("padded[%d] = 0x%02X, want 0x%02X", i, padded[i], expectedPadding)
		}
	}
}
