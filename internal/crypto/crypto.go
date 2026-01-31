// Package crypto provides cryptographic primitives for the Secret Service API
// dh-ietf1024-sha256-aes128-cbc-pkcs7 algorithm.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// Second Oakley Group (RFC 2409) - used as "dh-ietf1024" in Secret Service API
var (
	modp1024Prime = func() *big.Int {
		p, _ := new(big.Int).SetString(
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
				"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
				"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
				"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
				"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
				"FFFFFFFFFFFFFFFF", 16)
		return p
	}()
	modp1024Generator = big.NewInt(2)
)

const (
	// DHKeyBytes is the size of DH public keys in bytes (1024 bits)
	DHKeyBytes = 1024 / 8
	// AESKeyBytes is the size of derived AES keys (128 bits)
	AESKeyBytes = 128 / 8
	// AESBlockBytes is the AES block size
	AESBlockBytes = aes.BlockSize
)

// DHKeyPair holds DH key exchange results
type DHKeyPair struct {
	PublicKey  []byte // Our public key to send to peer
	SharedKey  []byte // Shared secret for key derivation
	PrivateKey *big.Int
}

// GenerateDHKeyPair generates a new DH key pair and computes the shared secret.
// The peerPublicKey may be shorter than DHKeyBytes if leading zeros were omitted
// (common with big-endian integer serialization). Keys longer than DHKeyBytes are rejected.
func GenerateDHKeyPair(peerPublicKey []byte) (*DHKeyPair, error) {
	if len(peerPublicKey) == 0 {
		return nil, fmt.Errorf("invalid peer public key: empty")
	}
	if len(peerPublicKey) > DHKeyBytes {
		return nil, fmt.Errorf("invalid peer public key size: expected at most %d, got %d", DHKeyBytes, len(peerPublicKey))
	}

	// Left-pad with zeros if shorter than DHKeyBytes (leading zeros may have been omitted)
	var padded []byte
	if len(peerPublicKey) < DHKeyBytes {
		padded = make([]byte, DHKeyBytes)
		copy(padded[DHKeyBytes-len(peerPublicKey):], peerPublicKey)
	} else {
		padded = peerPublicKey
	}

	// Parse peer's public key
	peerPubKeyInt := new(big.Int).SetBytes(padded)

	// Validate peer public key is in valid range (1 < peer < p-1)
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(modp1024Prime, one)
	if peerPubKeyInt.Cmp(one) <= 0 || peerPubKeyInt.Cmp(pMinus1) >= 0 {
		return nil, fmt.Errorf("invalid peer public key: out of range")
	}

	// Generate our private key: random value in [1, p-2]
	ourPrivKey, err := rand.Int(rand.Reader, pMinus1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	if ourPrivKey.Sign() == 0 {
		ourPrivKey.SetInt64(1)
	}

	// Compute our public key: g^privkey mod p
	ourPubKey := new(big.Int).Exp(modp1024Generator, ourPrivKey, modp1024Prime)

	// Compute shared secret: peer_pubkey^privkey mod p
	sharedSecret := new(big.Int).Exp(peerPubKeyInt, ourPrivKey, modp1024Prime)

	// Convert to fixed-size byte arrays
	pubKeyBytes := make([]byte, DHKeyBytes)
	sharedKeyBytes := make([]byte, DHKeyBytes)

	ourPubKey.FillBytes(pubKeyBytes)
	sharedSecret.FillBytes(sharedKeyBytes)

	return &DHKeyPair{
		PublicKey:  pubKeyBytes,
		SharedKey:  sharedKeyBytes,
		PrivateKey: ourPrivKey,
	}, nil
}

// ComputeSharedSecret computes the shared secret with a new peer public key
// using this key pair's existing private key. This is used when the other party
// sends their public key after we've already generated our key pair.
//
// This method is essential for proper DH key exchange:
// 1. Party A generates key pair (with dummy peer key)
// 2. Party A sends public key to Party B
// 3. Party B generates key pair using A's public key (B now has shared secret)
// 4. Party B sends public key to Party A
// 5. Party A calls ComputeSharedSecret with B's public key (A now has shared secret)
// Both parties now have the same shared secret.
func (kp *DHKeyPair) ComputeSharedSecret(peerPublicKey []byte) ([]byte, error) {
	if kp.PrivateKey == nil {
		return nil, fmt.Errorf("private key not available")
	}
	if len(peerPublicKey) == 0 {
		return nil, fmt.Errorf("invalid peer public key: empty")
	}
	if len(peerPublicKey) > DHKeyBytes {
		return nil, fmt.Errorf("invalid peer public key size: expected at most %d, got %d", DHKeyBytes, len(peerPublicKey))
	}

	// Left-pad with zeros if shorter than DHKeyBytes
	var padded []byte
	if len(peerPublicKey) < DHKeyBytes {
		padded = make([]byte, DHKeyBytes)
		copy(padded[DHKeyBytes-len(peerPublicKey):], peerPublicKey)
	} else {
		padded = peerPublicKey
	}

	// Parse peer's public key
	peerPubKeyInt := new(big.Int).SetBytes(padded)

	// Validate peer public key range (1 < peer < p-1)
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(modp1024Prime, one)
	if peerPubKeyInt.Cmp(one) <= 0 || peerPubKeyInt.Cmp(pMinus1) >= 0 {
		return nil, fmt.Errorf("invalid peer public key: out of range")
	}

	// Compute shared secret: peer_pubkey^privkey mod p
	sharedSecret := new(big.Int).Exp(peerPubKeyInt, kp.PrivateKey, modp1024Prime)

	// Convert to fixed-size byte array
	sharedKeyBytes := make([]byte, DHKeyBytes)
	sharedSecret.FillBytes(sharedKeyBytes)

	return sharedKeyBytes, nil
}

// DeriveAESKey derives a 128-bit AES key from the shared secret using HKDF-SHA256
func DeriveAESKey(sharedSecret []byte) ([]byte, error) {
	// HKDF with empty salt and empty info, as per Secret Service spec
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, nil)

	aesKey := make([]byte, AESKeyBytes)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, fmt.Errorf("failed to derive AES key: %w", err)
	}

	return aesKey, nil
}

// Encrypt encrypts plaintext using AES-128-CBC with PKCS7 padding
// Returns (ciphertext, iv)
func Encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	if len(key) != AESKeyBytes {
		return nil, nil, fmt.Errorf("invalid key size: expected %d, got %d", AESKeyBytes, len(key))
	}

	// Generate random IV
	iv := make([]byte, AESBlockBytes)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Apply PKCS7 padding
	padded := pkcs7Pad(plaintext, AESBlockBytes)

	// Encrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, iv, nil
}

// Decrypt decrypts ciphertext using AES-128-CBC with PKCS7 padding
func Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != AESKeyBytes {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", AESKeyBytes, len(key))
	}
	if len(iv) != AESBlockBytes {
		return nil, fmt.Errorf("invalid IV size: expected %d, got %d", AESBlockBytes, len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%AESBlockBytes != 0 {
		return nil, fmt.Errorf("invalid ciphertext size: must be multiple of %d", AESBlockBytes)
	}

	// Decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	return pkcs7Unpad(plaintext, AESBlockBytes)
}

// pkcs7Pad applies PKCS7 padding to data
// Returns a new slice with padding applied, does not mutate the input.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	result := make([]byte, len(data)+padding)
	copy(result, data)
	for i := 0; i < padding; i++ {
		result[len(data)+i] = byte(padding)
	}
	return result
}

// pkcs7Unpad removes PKCS7 padding from data
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data not aligned to block size")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding value: %d", padding)
	}

	// Verify all padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}
