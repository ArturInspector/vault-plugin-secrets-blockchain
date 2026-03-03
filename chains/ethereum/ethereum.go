package ethereum

import (
	"errors"

	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
)

func init() {
	chains.Register("ethereum", &Chain{})
}

type Chain struct{}

func (Chain) Name() string { return "ethereum" }

func (Chain) SignRaw(key, hash []byte) ([]byte, error) {
	return nil, errors.New("")
}

func (Chain) Sign(key, payload []byte) ([]byte, error) {
	return nil, errors.New("")
}

func (Chain) DeriveAddress(key []byte) (string, error) {
	return "", errors.New("")
}
