package bitcoin

import (
	"errors"

	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
)

func init() {
	chains.Register("bitcoin", &Chain{})
}

// Chain implements chains.Chain for Bitcoin (secp256k1).
type Chain struct{}

func (Chain) Name() string { return "bitcoin" }

func (Chain) SignRaw(key, hash []byte) ([]byte, error) {
	return nil, errors.New("bitcoin: not implemented")
}

func (Chain) Sign(key, payload []byte) ([]byte, error) {
	return nil, errors.New("bitcoin: not implemented")
}

func (Chain) DeriveAddress(key []byte) (string, error) {
	return "", errors.New("bitcoin: not implemented")
}
