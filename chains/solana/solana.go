package solana

import (
	"fmt"

	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"
)

func init() {
	chains.Register("solana", &Chain{})
}

// Chain implements ed25519 signing for Solana.
type Chain struct{}

func (Chain) Name() string { return "solana" }

// SignRaw signs the message (hash bytes) with ed25519; returns 64-byte signature.
func (Chain) SignRaw(key, hash []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("solana private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if len(hash) == 0 {
		return nil, fmt.Errorf("hash must not be empty")
	}
	priv := ed25519.PrivateKey(key)
	sig := ed25519.Sign(priv, hash)
	return sig, nil
}

// Sign signs an arbitrary payload (ed25519 signs the message directly).
func (c Chain) Sign(key, payload []byte) ([]byte, error) {
	return c.SignRaw(key, payload)
}

// DeriveAddress returns base58-encoded public key (Solana address).
func (Chain) DeriveAddress(key []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("solana private key must be %d bytes", ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(key)
	pub := priv.Public().(ed25519.PublicKey)
	return base58.Encode(pub), nil
}
