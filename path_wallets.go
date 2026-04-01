package kv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type WalletState string
type WalletTier string

const (
	StateOperational WalletState = "operational"
	StateFrozen      WalletState = "frozen"

	TierHot  WalletTier = "hot"
	TierWarm WalletTier = "warm"
	TierCold WalletTier = "cold"
)

type walletEntry struct {
	PrivateKey  string      `json:"private_key"`
	Address     string      `json:"address"`
	State       WalletState `json:"state"`
	Tier        WalletTier  `json:"tier"`
	FreezeNote  string      `json:"freeze_note,omitempty"`
}

func pathWallets(b *blockchainBackend) []*framework.Path {
	chainField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Chain name (ethereum|bitcoin|solana).",
	}
	nameField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Wallet name.",
	}
	tierField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Wallet tier: hot (default) | warm | cold.",
		Default:     "hot",
	}

	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/%s", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"chain": chainField,
				"name":  nameField,
				"tier":  tierField,
			},
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleWalletCreate},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWalletCreate},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleWalletRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleWalletDelete},
			},
			HelpSynopsis: "Create/read/delete a wallet; creation generates a new private key.",
		},
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/%s/import", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"chain":       chainField,
				"name":        nameField,
				"tier":        tierField,
				"private_key": {Type: framework.TypeString, Description: "Hex-encoded private key."},
			},
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleWalletImport},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWalletImport},
			},
			HelpSynopsis: "Import an existing private key for the wallet.",
		},
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/%s/rotate", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"chain": chainField,
				"name":  nameField,
			},
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleWalletRotate},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWalletRotate},
			},
			HelpSynopsis: "Rotate wallet key (generates a new private key, overwriting the old one).",
		},
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/", framework.GenericNameRegex("chain")),
			Fields: map[string]*framework.FieldSchema{
				"chain": chainField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handleWalletList},
			},
			HelpSynopsis: "List wallet names for a chain.",
		},
	}
}

func (b *blockchainBackend) handleWalletCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	chain := chains.Get(chainName)
	if chain == nil {
		return logical.ErrorResponse("unknown chain"), nil
	}

	keyBytes, err := chain.GenerateKey()
	if err != nil {
		return nil, err
	}

	addr, err := chain.DeriveAddress(keyBytes)
	if err != nil {
		return nil, err
	}

	entry := walletEntry{
		PrivateKey: hex.EncodeToString(keyBytes),
		Address:    addr,
		State:      StateOperational,
		Tier:       resolveTier(data),
	}

	exists, err := b.walletExists(ctx, req.Storage, chainName, walletName)
	if err != nil {
		return nil, err
	}
	if exists {
		return logical.ErrorResponse("wallet already exists"), nil
	}

	if err := b.writeWallet(ctx, req.Storage, chainName, walletName, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": entry.Address,
		},
	}, nil
}

func (b *blockchainBackend) handleWalletImport(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	chain := chains.Get(chainName)
	if chain == nil {
		return logical.ErrorResponse("unknown chain"), nil
	}

	privHex := data.Get("private_key").(string)
	if privHex == "" {
		return logical.ErrorResponse("missing private_key"), nil
	}
	keyBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return logical.ErrorResponse("private_key must be hex"), nil
	}

	if len(keyBytes) == 0 {
		return logical.ErrorResponse("private_key must not be empty"), nil
	}

	addr, err := chain.DeriveAddress(keyBytes)
	if err != nil {
		return nil, err
	}

	entry := walletEntry{
		PrivateKey: privHex,
		Address:    addr,
		State:      StateOperational,
		Tier:       resolveTier(data),
	}

	if err := b.writeWallet(ctx, req.Storage, chainName, walletName, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": entry.Address,
		},
	}, nil
}

func (b *blockchainBackend) handleWalletRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	chain := chains.Get(chainName)
	if chain == nil {
		return logical.ErrorResponse("unknown chain"), nil
	}

	exists, err := b.walletExists(ctx, req.Storage, chainName, walletName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return logical.ErrorResponse("wallet not found"), nil
	}

	keyBytes, err := chain.GenerateKey()
	if err != nil {
		return nil, err
	}
	addr, err := chain.DeriveAddress(keyBytes)
	if err != nil {
		return nil, err
	}

	existing, err := b.readWallet(ctx, req.Storage, chainName, walletName)
	if err != nil {
		return nil, err
	}

	tier := TierHot
	if existing != nil {
		tier = existing.Tier
	}

	entry := walletEntry{
		PrivateKey: hex.EncodeToString(keyBytes),
		Address:    addr,
		State:      StateOperational,
		Tier:       tier,
	}

	if err := b.writeWallet(ctx, req.Storage, chainName, walletName, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": entry.Address,
		},
	}, nil
}

func (b *blockchainBackend) handleWalletRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := b.readWallet(ctx, req.Storage, chainName, walletName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	out := map[string]interface{}{
		"address": entry.Address,
		"state":   string(entry.State),
		"tier":    string(entry.Tier),
	}
	if entry.State == StateFrozen && entry.FreezeNote != "" {
		out["freeze_note"] = entry.FreezeNote
	}
	return &logical.Response{Data: out}, nil
}

func (b *blockchainBackend) handleWalletDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := b.readWallet(ctx, req.Storage, chainName, walletName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("wallet not found"), nil
	}
	if entry.State != StateFrozen {
		return logical.ErrorResponse("wallet must be frozen before deletion (freeze first, then delete)"), nil
	}

	if err := req.Storage.Delete(ctx, b.walletKey(chainName, walletName)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *blockchainBackend) handleWalletList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName := data.Get("chain").(string)
	if chainName == "" {
		return logical.ErrorResponse("missing chain"), nil
	}

	prefix := path.Join(b.storagePrefix, "wallets", chainName) + "/"
	keys, err := req.Storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(keys), nil
}

func (b *blockchainBackend) walletKey(chainName, walletName string) string {
	return path.Join(b.storagePrefix, "wallets", chainName, walletName)
}

func (b *blockchainBackend) walletExists(ctx context.Context, s logical.Storage, chainName, walletName string) (bool, error) {
	raw, err := s.Get(ctx, b.walletKey(chainName, walletName))
	if err != nil {
		return false, err
	}
	return raw != nil, nil
}

func (b *blockchainBackend) readWallet(ctx context.Context, s logical.Storage, chainName, walletName string) (*walletEntry, error) {
	raw, err := s.Get(ctx, b.walletKey(chainName, walletName))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var entry walletEntry
	if err := raw.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (b *blockchainBackend) writeWallet(ctx context.Context, s logical.Storage, chainName, walletName string, entry walletEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{
		Key:   b.walletKey(chainName, walletName),
		Value: payload,
	})
}

func (b *blockchainBackend) handleWalletExists(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return false, nil
	}
	return b.walletExists(ctx, req.Storage, chainName, walletName)
}

func readChainAndName(data *framework.FieldData) (string, string, error) {
	chainName := data.Get("chain").(string)
	walletName := data.Get("name").(string)
	if chainName == "" {
		return "", "", errors.New("missing chain")
	}
	if walletName == "" {
		return "", "", errors.New("missing name")
	}
	return chainName, walletName, nil
}

func resolveTier(data *framework.FieldData) WalletTier {
	if raw, ok := data.GetOk("tier"); ok {
		switch raw.(string) {
		case "warm":
			return TierWarm
		case "cold":
			return TierCold
		}
	}
	return TierHot
}

