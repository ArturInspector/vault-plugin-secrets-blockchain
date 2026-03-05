package bitcoin

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
)

func init() {
	chains.Register("bitcoin", &Chain{})
}

type Chain struct{}

func (Chain) Name() string { return "bitcoin" }

// 32-byte hash
func (Chain) SignRaw(key, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}
	priv := secp256k1.PrivKeyFromBytes(key)
	sig := ecdsa.Sign(priv, hash).Serialize()
	return sig, nil
}

// returns DER signature.
func (c Chain) Sign(key, payload []byte) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload must be 32-byte hash, got %d", len(payload))
	}
	return c.SignRaw(key, payload)
}

func (Chain) DeriveAddress(key []byte) (string, error) {
	priv := secp256k1.PrivKeyFromBytes(key)
	pubCompressed := priv.PubKey().SerializeCompressed()
	hash160 := btcutil.Hash160(pubCompressed)
	addr, err := btcutil.NewAddressWitnessPubKeyHash(hash160, &chaincfg.MainNetParams)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}
