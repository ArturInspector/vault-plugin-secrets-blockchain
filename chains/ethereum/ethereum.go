package ethereum

import (
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"golang.org/x/crypto/sha3"
)

func init() {
	chains.Register("ethereum", &Chain{})
}

// Chain implements secp256k1 signing for Ethereum.
type Chain struct{}

func (Chain) Name() string { return "ethereum" }

// SignRaw signs a 32-byte hash and returns R||S||V (V is recovery id 0/1).
func (Chain) SignRaw(key, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}
	priv := secp256k1.PrivKeyFromBytes(key)
	sigCompact := ecdsa.SignCompact(priv, hash, false)
	if len(sigCompact) != 65 {
		return nil, fmt.Errorf("unexpected compact signature size %d", len(sigCompact))
	}
	v := sigCompact[0]
	// normalize V to {0,1}
	if v < 27 {
		return nil, fmt.Errorf("invalid recovery id %d", v)
	}
	recID := v - 27
	r := sigCompact[1:33]
	s := sigCompact[33:65]
	sig := append(append([]byte{}, r...), s...)
	sig = append(sig, recID)
	return sig, nil
}

// Returns R||S||V.
func (c Chain) Sign(key, payload []byte) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload must be 32-byte hash, got %d", len(payload))
	}
	return c.SignRaw(key, payload)
}

// 0x +keccak256(pubkey[1:])[12:].
func (Chain) DeriveAddress(key []byte) (string, error) {
	priv := secp256k1.PrivKeyFromBytes(key)
	pub := priv.PubKey().SerializeUncompressed()
	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(pub[1:]) // drop 0x04 prefix
	hash := keccak.Sum(nil)
	addr := hash[12:]
	return "0x" + hex.EncodeToString(addr), nil
}
