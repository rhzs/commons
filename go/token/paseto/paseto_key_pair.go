package pasetotoken

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/vk-rv/pvx"
)

// PasetoKeyPair contains Paseto public and secret key functions
type PasetoKeyPair interface {
	GetPublicKey() *pvx.AsymPublicKey
	GetSecretKey() *pvx.AsymSecretKey
}

// PasetoKeys contains public and secret key values
type PasetoKeys struct {
	publicKey *pvx.AsymPublicKey
	secretKey *pvx.AsymSecretKey
}

// NewPasetoKeyPair gets Paseto Key
func NewPasetoKeyPair(publicKey []byte, privateKey []byte) PasetoKeyPair {
	sk := pvx.NewAsymmetricSecretKey(privateKey, pvx.Version4)
	pk := pvx.NewAsymmetricPublicKey(publicKey, pvx.Version4)

	return &PasetoKeys{
		publicKey: pk,
		secretKey: sk,
	}
}

// GetPublicKey get public key
func (key *PasetoKeys) GetPublicKey() *pvx.AsymPublicKey {
	return key.publicKey
}

// GetSecretKey gets secret key
func (key *PasetoKeys) GetSecretKey() *pvx.AsymSecretKey {
	return key.secretKey
}

// createPasetoTokenWithED25519 used for testing only
func createPasetoTokenWithED25519() PasetoKeyPair {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	strpub := hex.EncodeToString(publicKey)
	fmt.Println("PUB: ", strpub)

	priv := hex.EncodeToString(privateKey)
	fmt.Println("PRIV: ", priv)

	pkp := NewPasetoKeyPair(publicKey, privateKey)

	return pkp
}
