package dbus

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// dhGroup represents a Diffie-Hellman group
type dhGroup struct {
	g, p, pMinus1 *big.Int
}

var bigOne = big.NewInt(1)

// NewKeypair generates a new DH keypair
func (dg *dhGroup) NewKeypair() (private, public *big.Int, err error) {
	for {
		if private, err = cryptorand.Int(cryptorand.Reader, dg.pMinus1); err != nil {
			return nil, nil, err
		}
		if private.Sign() > 0 {
			break
		}
	}
	public = new(big.Int).Exp(dg.g, private, dg.p)
	return private, public, nil
}

// diffieHellman computes the shared secret
func (dg *dhGroup) diffieHellman(theirPublic, myPrivate *big.Int) (*big.Int, error) {
	if theirPublic.Cmp(bigOne) <= 0 || theirPublic.Cmp(dg.pMinus1) >= 0 {
		return nil, errors.New("DH parameter out of bounds")
	}
	return new(big.Int).Exp(theirPublic, myPrivate, dg.p), nil
}

// rfc2409SecondOakleyGroup returns the IETF 1024-bit MODP group (RFC 2409)
func rfc2409SecondOakleyGroup() *dhGroup {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	return &dhGroup{
		g:       new(big.Int).SetInt64(2),
		p:       p,
		pMinus1: new(big.Int).Sub(p, bigOne),
	}
}

// keygenHKDFSHA256AES128 derives a 128-bit AES key from the DH shared secret
func (dg *dhGroup) keygenHKDFSHA256AES128(theirPublic *big.Int, myPrivate *big.Int) ([]byte, error) {
	sharedSecret, err := dg.diffieHellman(theirPublic, myPrivate)
	if err != nil {
		return nil, err
	}

	r := hkdf.New(sha256.New, sharedSecret.Bytes(), nil, nil)
	aesKey := make([]byte, 16)
	if _, err := io.ReadFull(r, aesKey); err != nil {
		return nil, err
	}
	return aesKey, nil
}
