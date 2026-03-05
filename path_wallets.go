package kv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/ed25519"
)

type walletEntry struct {
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
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

	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/%s", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"chain": chainField,
				"name":  nameField,
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

	keyBytes, err := generatePrivateKey(chainName)
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

	if err := validatePrivateKey(chainName, keyBytes); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	addr, err := chain.DeriveAddress(keyBytes)
	if err != nil {
		return nil, err
	}

	entry := walletEntry{
		PrivateKey: privHex,
		Address:    addr,
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

	keyBytes, err := generatePrivateKey(chainName)
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

	return &logical.Response{
		Data: map[string]interface{}{
			"address": entry.Address,
		},
	}, nil
}

func (b *blockchainBackend) handleWalletDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName, walletName, err := readChainAndName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
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

func generatePrivateKey(chainName string) ([]byte, error) {
	switch chainName {
	case "ethereum", "bitcoin":
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		return priv.Serialize(), nil
	case "solana":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported chain %q", chainName)
	}
}

func validatePrivateKey(chainName string, key []byte) error {
	switch chainName {
	case "ethereum", "bitcoin":
		if len(key) != 32 {
			return fmt.Errorf("secp256k1 key must be 32 bytes, got %d", len(key))
		}
		_ = secp256k1.PrivKeyFromBytes(key) // validates range
		return nil
	case "solana":
		if len(key) != ed25519.PrivateKeySize {
			return fmt.Errorf("solana private key must be %d bytes", ed25519.PrivateKeySize)
		}
		return nil
	default:
		return fmt.Errorf("unsupported chain %q", chainName)
	}
}
