package kv

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestHD_InitAndRead(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("hd init: err=%v resp=%v", err, resp)
	}
	seed, ok := resp.Data["seed"].(string)
	if !ok || len(seed) != 128 {
		t.Fatalf("expected 128-char hex seed, got %q", seed)
	}
	fp, ok := resp.Data["fingerprint"].(string)
	if !ok || len(fp) != 8 {
		t.Fatalf("expected 8-char fingerprint, got %q", fp)
	}

	resp, err = b.HandleRequest(ctx, req(logical.ReadOperation, "chains/ethereum/hd", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("hd read: %v %v", err, resp)
	}
	if resp.Data["fingerprint"] != fp {
		t.Fatalf("fingerprint mismatch: %v vs %v", resp.Data["fingerprint"], fp)
	}
	if resp.Data["child_count"] != uint32(0) {
		t.Fatalf("expected child_count=0, got %v", resp.Data["child_count"])
	}
}

func TestHD_InitTwiceIsError(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s))
	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error on second init")
	}
}

func TestHD_DeriveAutoIncrement(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s))

	addresses := make(map[string]bool)
	for i := 0; i < 5; i++ {
		resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive", nil, s))
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("derive #%d: err=%v resp=%v", i, err, resp)
		}
		addr := resp.Data["address"].(string)
		if addresses[addr] {
			t.Fatalf("derive #%d: duplicate address %s", i, addr)
		}
		addresses[addr] = true

		idx := resp.Data["index"].(uint32)
		if idx != uint32(i) {
			t.Fatalf("derive #%d: expected index=%d, got %d", i, i, idx)
		}

		derivation := resp.Data["derivation"].(string)
		if !strings.HasPrefix(derivation, "m/44'/60'/0'/0/") {
			t.Fatalf("unexpected derivation path: %s", derivation)
		}
	}

	resp, _ := b.HandleRequest(ctx, req(logical.ReadOperation, "chains/ethereum/hd", nil, s))
	if resp.Data["child_count"] != uint32(5) {
		t.Fatalf("expected child_count=5, got %v", resp.Data["child_count"])
	}
}

func TestHD_DeriveExplicitIndex(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive",
		map[string]interface{}{"index": 42, "name": "wallet-42"}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("derive index=42: err=%v resp=%v", err, resp)
	}
	if resp.Data["index"] != uint32(42) {
		t.Fatalf("expected index=42, got %v", resp.Data["index"])
	}
	if resp.Data["name"] != "wallet-42" {
		t.Fatalf("expected name=wallet-42, got %v", resp.Data["name"])
	}
	if resp.Data["derivation"] != "m/44'/60'/0'/0/42" {
		t.Fatalf("unexpected derivation: %v", resp.Data["derivation"])
	}
}

func TestHD_DerivedWalletCanSign(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s))
	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive",
		map[string]interface{}{"name": "hot-hd-0"}, s))

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/hot-hd-0/sign_raw",
		map[string]interface{}{"hash": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sign_raw on HD wallet: err=%v resp=%v", err, resp)
	}
	sig := resp.Data["signature"].(string)
	if len(sig) != 130 {
		t.Fatalf("expected 130-char hex sig (65 bytes), got len=%d", len(sig))
	}
}

func TestHD_SeedImport(t *testing.T) {
	ctx := context.Background()

	b1, s1 := newBlockchainBackend(t)
	resp, _ := b1.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd", nil, s1))
	seed := resp.Data["seed"].(string)
	fp1 := resp.Data["fingerprint"].(string)

	b1.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive", nil, s1))
	respDerive, _ := b1.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive", nil, s1))
	addr0 := respDerive.Data["address"].(string)

	b2, s2 := newBlockchainBackend(t)
	resp2, err := b2.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd",
		map[string]interface{}{"mnemonic": seed}, s2))
	if err != nil || (resp2 != nil && resp2.IsError()) {
		t.Fatalf("import seed: err=%v resp=%v", err, resp2)
	}
	fp2 := resp2.Data["fingerprint"].(string)
	if fp1 != fp2 {
		t.Fatalf("fingerprint mismatch after import: %s vs %s", fp1, fp2)
	}

	b2.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive", nil, s2))
	respDerive2, _ := b2.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/hd/derive", nil, s2))
	addr0restored := respDerive2.Data["address"].(string)

	if addr0 != addr0restored {
		t.Fatalf("address mismatch after seed import: original=%s restored=%s", addr0, addr0restored)
	}
}

func TestHD_BitcoinDerivation(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/bitcoin/hd", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("btc hd init: %v %v", err, resp)
	}

	resp, err = b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/bitcoin/hd/derive", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("btc derive: %v %v", err, resp)
	}
	addr := resp.Data["address"].(string)
	if !strings.HasPrefix(addr, "bc1") {
		t.Fatalf("expected bech32 btc address, got %s", addr)
	}
	if resp.Data["derivation"] != "m/44'/0'/0'/0/0" {
		t.Fatalf("unexpected btc derivation: %v", resp.Data["derivation"])
	}
}

func TestHD_UnsupportedChain(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/solana/hd", nil, s))
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for solana HD (not supported)")
	}
}
