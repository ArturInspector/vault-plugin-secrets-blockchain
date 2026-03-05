package kv

import (
	"context"
	"fmt"
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
	if conf.BackendUUID == "" {
		return nil, fmt.Errorf("backend uuid is required")
	}

	b := &blockchainBackend{
		storagePrefix: path.Join(conf.BackendUUID, blockchainStoragePrefix),
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Blockchain signing backend",

		PathsSpecial: &logical.Paths{
			// Seal wrap all wallet records (includes private keys).
			SealWrapStorage: []string{
				path.Join(b.storagePrefix, "wallets") + "/",
			},
		},

		Paths: framework.PathAppend(
			pathWallets(b),
			pathSign(b),
			pathSignRaw(b),
		),
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}
