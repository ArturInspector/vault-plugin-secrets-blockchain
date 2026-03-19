package kv

import (
	"context"
	"path"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// blockchainStoragePrefix is the root prefix for blockchain wallets and keys.
	blockchainStoragePrefix = "blockchain"
)

// blockchainBackend implements logical.Backend for blockchain signing.
type blockchainBackend struct {
	*framework.Backend
	storagePrefix string
}

var _ logical.Backend = &blockchainBackend{}

// BlockchainFactory returns a blockchain signing backend.
func BlockchainFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	prefix := conf.BackendUUID
	if prefix == "" {
		prefix = "default"
	}

	b := &blockchainBackend{
		storagePrefix: path.Join(prefix, blockchainStoragePrefix),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Blockchain signing backend",

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				path.Join(b.storagePrefix, "wallets") + "/",
				path.Join(b.storagePrefix, "hd") + "/",
			},
		},

		Paths: framework.PathAppend(
			pathWallets(b),
			pathWalletState(b),
			pathSign(b),
			pathSignRaw(b),
			pathHD(b),
		),
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}
