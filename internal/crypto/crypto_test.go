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

// --- DH Key Pair Tests ---

func TestGenerateDHKeyPair_FullSizeKey(t *testing.T) {
	// Create a valid 128-byte peer public key (a small valid value, left-padded)
	peerKey := make([]byte, DHKeyBytes)
	peerKey[DHKeyBytes-1] = 0x42 // Valid: 66 (greater than 1, less than p-1)

	result, err := GenerateDHKeyPair(peerKey)
	if err != nil {
		t.Fatalf("GenerateDHKeyPair failed: %v", err)
	}

	// Verify output sizes are fixed at 128 bytes
	if len(result.PublicKey) != DHKeyBytes {
		t.Errorf("PublicKey size = %d, want %d", len(result.PublicKey), DHKeyBytes)
	}
	if len(result.SharedKey) != DHKeyBytes {
		t.Errorf("SharedKey size = %d, want %d", len(result.SharedKey), DHKeyBytes)
	}
}

func TestGenerateDHKeyPair_AcceptsShortKey(t *testing.T) {
	// Real clients may omit leading zeros from big-endian integers.
	// A valid public key like 0x42 (66) would be sent as just []byte{0x42}.
	shortKey := []byte{0x42} // Valid: 66 (greater than 1, less than p-1)

	result, err := GenerateDHKeyPair(shortKey)
	if err != nil {
		t.Fatalf("GenerateDHKeyPair should accept short keys: %v", err)
	}

	// Verify output sizes are still fixed at 128 bytes
	if len(result.PublicKey) != DHKeyBytes {
		t.Errorf("PublicKey size = %d, want %d", len(result.PublicKey), DHKeyBytes)
	}
	if len(result.SharedKey) != DHKeyBytes {
		t.Errorf("SharedKey size = %d, want %d", len(result.SharedKey), DHKeyBytes)
	}
}

func TestGenerateDHKeyPair_AcceptsVariableLengthKeys(t *testing.T) {
	// Test various valid key lengths (all represent the same value: 1000)
	testCases := []struct {
		name string
		key  []byte
	}{
		{"2 bytes", []byte{0x03, 0xE8}},             // 1000 in 2 bytes
		{"3 bytes", []byte{0x00, 0x03, 0xE8}},       // 1000 in 3 bytes (with leading zero)
		{"4 bytes", []byte{0x00, 0x00, 0x03, 0xE8}}, // 1000 in 4 bytes
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GenerateDHKeyPair(tc.key)
			if err != nil {
				t.Fatalf("GenerateDHKeyPair failed for %s: %v", tc.name, err)
			}
			if len(result.PublicKey) != DHKeyBytes {
				t.Errorf("PublicKey size = %d, want %d", len(result.PublicKey), DHKeyBytes)
			}
		})
	}
}

func TestGenerateDHKeyPair_RejectsOversizedKey(t *testing.T) {
	// Keys longer than 128 bytes should be rejected
	oversizedKey := make([]byte, DHKeyBytes+1)
	oversizedKey[0] = 0x01 // Non-zero to be a valid integer

	_, err := GenerateDHKeyPair(oversizedKey)
	if err == nil {
		t.Error("GenerateDHKeyPair should reject keys > 128 bytes")
	}
}

func TestGenerateDHKeyPair_RejectsEmptyKey(t *testing.T) {
	_, err := GenerateDHKeyPair([]byte{})
	if err == nil {
		t.Error("GenerateDHKeyPair should reject empty keys")
	}
}

func TestGenerateDHKeyPair_RejectsZeroKey(t *testing.T) {
	// Key value of 0 is invalid (must be > 1)
	zeroKey := make([]byte, DHKeyBytes)

	_, err := GenerateDHKeyPair(zeroKey)
	if err == nil {
		t.Error("GenerateDHKeyPair should reject zero key (out of range)")
	}
}

func TestGenerateDHKeyPair_RejectsOneKey(t *testing.T) {
	// Key value of 1 is invalid (must be > 1)
	oneKey := make([]byte, DHKeyBytes)
	oneKey[DHKeyBytes-1] = 0x01

	_, err := GenerateDHKeyPair(oneKey)
	if err == nil {
		t.Error("GenerateDHKeyPair should reject key value 1 (out of range)")
	}
}

func TestGenerateDHKeyPair_RejectsShortOneKey(t *testing.T) {
	// Short key representing value 1 is also invalid
	oneKey := []byte{0x01}

	_, err := GenerateDHKeyPair(oneKey)
	if err == nil {
		t.Error("GenerateDHKeyPair should reject short key value 1 (out of range)")
	}
}

func TestDeriveAESKey_ProducesCorrectSize(t *testing.T) {
	// Use a valid shared secret
	sharedSecret := bytes.Repeat([]byte{0x42}, DHKeyBytes)

	aesKey, err := DeriveAESKey(sharedSecret)
	if err != nil {
		t.Fatalf("DeriveAESKey failed: %v", err)
	}

	if len(aesKey) != AESKeyBytes {
		t.Errorf("AES key size = %d, want %d", len(aesKey), AESKeyBytes)
	}
}

func TestDHKeyExchange_Roundtrip(t *testing.T) {
	// Simulate a proper DH key exchange between two parties
	// This test verifies both parties derive the SAME shared secret

	// Party A generates initial key pair with a dummy peer key
	dummyPeerA := make([]byte, DHKeyBytes)
	dummyPeerA[DHKeyBytes-1] = 0x42

	pairA, err := GenerateDHKeyPair(dummyPeerA)
	if err != nil {
		t.Fatalf("Party A key generation failed: %v", err)
	}

	// Party B generates key pair using Party A's public key
	pairB, err := GenerateDHKeyPair(pairA.PublicKey)
	if err != nil {
		t.Fatalf("Party B key generation failed: %v", err)
	}

	// Party A computes shared secret using B's public key WITH A's ORIGINAL private key
	sharedKeyA, err := pairA.ComputeSharedSecret(pairB.PublicKey)
	if err != nil {
		t.Fatalf("Party A shared secret computation failed: %v", err)
	}

	// CRITICAL: Verify the shared secrets match
	if !bytes.Equal(sharedKeyA, pairB.SharedKey) {
		t.Errorf("Shared secrets don't match!\nA: %x\nB: %x", sharedKeyA, pairB.SharedKey)
	}

	// Derive AES keys and verify they match
	aesKeyA, err := DeriveAESKey(sharedKeyA)
	if err != nil {
		t.Fatalf("Party A AES derivation failed: %v", err)
	}
	aesKeyB, err := DeriveAESKey(pairB.SharedKey)
	if err != nil {
		t.Fatalf("Party B AES derivation failed: %v", err)
	}

	if !bytes.Equal(aesKeyA, aesKeyB) {
		t.Errorf("AES keys don't match!\nA: %x\nB: %x", aesKeyA, aesKeyB)
	}

	// Verify cross-party encryption works
	plaintext := []byte("secret message from Party A")
	ciphertext, iv, err := Encrypt(plaintext, aesKeyA)
	if err != nil {
		t.Fatalf("Encryption with A's key failed: %v", err)
	}
	decrypted, err := Decrypt(ciphertext, aesKeyB, iv)
	if err != nil {
		t.Fatalf("Decryption with B's key failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Cross-party encryption failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestComputeSharedSecret_Validation(t *testing.T) {
	dummyPeer := make([]byte, DHKeyBytes)
	dummyPeer[DHKeyBytes-1] = 0x42

	pair, err := GenerateDHKeyPair(dummyPeer)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	tests := []struct {
		name    string
		peerKey []byte
		wantErr bool
	}{
		{"empty key", []byte{}, true},
		{"zero key", make([]byte, DHKeyBytes), true},
		{"key value 1", []byte{0x01}, true},
		{"oversized key", make([]byte, DHKeyBytes+1), true},
		{"valid short key", []byte{0x42}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := pair.ComputeSharedSecret(tt.peerKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComputeSharedSecret() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestComputeSharedSecret_NilPrivateKey(t *testing.T) {
	pair := &DHKeyPair{
		PublicKey:  make([]byte, DHKeyBytes),
		SharedKey:  make([]byte, DHKeyBytes),
		PrivateKey: nil,
	}

	validPeer := make([]byte, DHKeyBytes)
	validPeer[DHKeyBytes-1] = 0x42

	_, err := pair.ComputeSharedSecret(validPeer)
	if err == nil {
		t.Error("ComputeSharedSecret should fail with nil private key")
	}
}
