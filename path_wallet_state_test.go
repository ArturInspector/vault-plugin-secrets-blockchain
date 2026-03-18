package kv

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestWalletState_DefaultIsOperational(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w1", nil, s))

	resp, _ := b.HandleRequest(ctx, req(logical.ReadOperation, "chains/ethereum/wallets/w1", nil, s))
	if resp.Data["state"] != string(StateOperational) {
		t.Fatalf("expected operational, got %v", resp.Data["state"])
	}
	if resp.Data["tier"] != string(TierHot) {
		t.Fatalf("expected hot, got %v", resp.Data["tier"])
	}
}

func TestWalletState_TierCold(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/cold1",
		map[string]interface{}{"tier": "cold"}, s))

	resp, _ := b.HandleRequest(ctx, req(logical.ReadOperation, "chains/ethereum/wallets/cold1", nil, s))
	if resp.Data["tier"] != string(TierCold) {
		t.Fatalf("expected cold, got %v", resp.Data["tier"])
	}
}

func TestWalletState_FreezeBlocksSigning(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w2", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w2/freeze",
		map[string]interface{}{"note": "suspicious activity"}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("freeze: err=%v resp=%v", err, resp)
	}
	if resp.Data["state"] != string(StateFrozen) {
		t.Fatalf("expected frozen, got %v", resp.Data["state"])
	}

	hash := hex.EncodeToString(make([]byte, 32))
	resp, err = b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w2/sign_raw",
		map[string]interface{}{"hash": hash}, s))
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error: signing frozen wallet must fail")
	}
}

func TestWalletState_UnfreezeRestoresSigning(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w3", nil, s))
	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w3/freeze", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w3/unfreeze", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("unfreeze: err=%v resp=%v", err, resp)
	}
	if resp.Data["state"] != string(StateOperational) {
		t.Fatalf("expected operational after unfreeze, got %v", resp.Data["state"])
	}

	hash := hex.EncodeToString(make([]byte, 32))
	resp, err = b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w3/sign_raw",
		map[string]interface{}{"hash": hash}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sign after unfreeze must succeed: err=%v resp=%v", err, resp)
	}
}

func TestWalletState_FreezeTwiceIsError(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w4", nil, s))
	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w4/freeze", nil, s))

	resp, _ := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w4/freeze", nil, s))
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error on double freeze")
	}
}

func TestWalletState_RotateKeepsState(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w5",
		map[string]interface{}{"tier": "warm"}, s))

	resp, _ := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/w5/rotate", nil, s))
	if resp != nil && resp.IsError() {
		t.Fatalf("rotate: %v", resp)
	}

	resp, _ = b.HandleRequest(ctx, req(logical.ReadOperation, "chains/ethereum/wallets/w5", nil, s))
	if resp.Data["tier"] != string(TierWarm) {
		t.Fatalf("tier must survive rotate: got %v", resp.Data["tier"])
	}
	if resp.Data["state"] != string(StateOperational) {
		t.Fatalf("state must be operational after rotate: got %v", resp.Data["state"])
	}
}
