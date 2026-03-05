package kv

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *blockchainBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/%s/sign", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"chain":   {Type: framework.TypeString, Description: "Chain name."},
				"name":    {Type: framework.TypeString, Description: "Wallet name."},
				"payload": {Type: framework.TypeString, Description: "Hex-encoded payload to sign (chain-specific)."},
			},
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSign},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSign},
			},
			HelpSynopsis: "Sign a chain-specific payload using the stored private key.",
		},
	}
}

func pathSignRaw(b *blockchainBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("chains/%s/wallets/%s/sign_raw", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields: map[string]*framework.FieldSchema{
				"chain": {Type: framework.TypeString, Description: "Chain name."},
				"name":  {Type: framework.TypeString, Description: "Wallet name."},
				"hash":  {Type: framework.TypeString, Description: "32-byte hash hex-encoded."},
			},
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSignRaw},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSignRaw},
			},
			HelpSynopsis: "Sign a raw 32-byte hash with the stored private key.",
		},
	}
}

func (b *blockchainBackend) handleSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName := data.Get("chain").(string)
	walletName := data.Get("name").(string)
	payloadHex := data.Get("payload").(string)
	if chainName == "" || walletName == "" {
		return logical.ErrorResponse("missing chain or name"), nil
	}
	if payloadHex == "" {
		return logical.ErrorResponse("missing payload"), nil
	}

	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		return logical.ErrorResponse("payload must be hex"), nil
	}

	entry, keyBytes, chain, resp, err := b.loadSigningContext(ctx, req, chainName, walletName)
	if err != nil {
		return resp, err
	}
	if resp != nil {
		return resp, nil
	}

	signed, err := chain.Sign(keyBytes, payload)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": entry.Address,
			"signed":  hex.EncodeToString(signed),
		},
	}, nil
}

func (b *blockchainBackend) handleSignRaw(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName := data.Get("chain").(string)
	walletName := data.Get("name").(string)
	hashHex := data.Get("hash").(string)
	if chainName == "" || walletName == "" {
		return logical.ErrorResponse("missing chain or name"), nil
	}
	if hashHex == "" {
		return logical.ErrorResponse("missing hash"), nil
	}

	hash, err := hex.DecodeString(hashHex)
	if err != nil {
		return logical.ErrorResponse("hash must be hex"), nil
	}
	if len(hash) == 0 {
		return logical.ErrorResponse("hash must not be empty"), nil
	}
	// Length validation is delegated to the chain implementation:
	// secp256k1 chains enforce exactly 32 bytes; ed25519 chains (Solana) accept arbitrary messages.

	entry, keyBytes, chain, resp, err := b.loadSigningContext(ctx, req, chainName, walletName)
	if err != nil {
		return resp, err
	}
	if resp != nil {
		return resp, nil
	}

	sig, err := chain.SignRaw(keyBytes, hash)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address":   entry.Address,
			"signature": hex.EncodeToString(sig),
		},
	}, nil
}

func (b *blockchainBackend) loadSigningContext(ctx context.Context, req *logical.Request, chainName, walletName string) (*walletEntry, []byte, chains.Chain, *logical.Response, error) {
	chain := chains.Get(chainName)
	if chain == nil {
		return nil, nil, nil, logical.ErrorResponse("unknown chain"), nil
	}

	entry, err := b.readWallet(ctx, req.Storage, chainName, walletName)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if entry == nil {
		return nil, nil, nil, logical.ErrorResponse("wallet not found"), nil
	}

	keyBytes, err := hex.DecodeString(entry.PrivateKey)
	if err != nil {
		return nil, nil, nil, nil, errors.New("stored private_key is invalid hex")
	}

	return entry, keyBytes, chain, nil, nil
}
