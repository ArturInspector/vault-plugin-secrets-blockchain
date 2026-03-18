package kv

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathWalletState(b *blockchainBackend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"chain": {Type: framework.TypeString, Description: "Chain name."},
		"name":  {Type: framework.TypeString, Description: "Wallet name."},
		"note":  {Type: framework.TypeString, Description: "Reason for freeze (optional)."},
	}

	return []*framework.Path{
		{
			Pattern:        fmt.Sprintf("chains/%s/wallets/%s/freeze", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields:         fields,
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleFreeze},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleFreeze},
			},
			HelpSynopsis: "Freeze a wallet. Signing will be rejected until unfrozen.",
		},
		{
			Pattern:        fmt.Sprintf("chains/%s/wallets/%s/unfreeze", framework.GenericNameRegex("chain"), framework.GenericNameRegex("name")),
			Fields:         fields,
			ExistenceCheck: b.handleWalletExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleUnfreeze},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleUnfreeze},
			},
			HelpSynopsis: "Unfreeze a wallet, restoring signing capability.",
		},
	}
}

func (b *blockchainBackend) handleFreeze(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if entry.State == StateFrozen {
		return logical.ErrorResponse("wallet is already frozen"), nil
	}

	note, _ := data.GetOk("note")
	entry.State = StateFrozen
	entry.FreezeNote, _ = note.(string)

	if err := b.writeWallet(ctx, req.Storage, chainName, walletName, *entry); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"address": entry.Address,
		"state":   string(entry.State),
		"note":    entry.FreezeNote,
	}}, nil
}

func (b *blockchainBackend) handleUnfreeze(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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
	if entry.State == StateOperational {
		return logical.ErrorResponse("wallet is already operational"), nil
	}

	entry.State = StateOperational
	entry.FreezeNote = ""

	if err := b.writeWallet(ctx, req.Storage, chainName, walletName, *entry); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"address": entry.Address,
		"state":   string(entry.State),
	}}, nil
}
