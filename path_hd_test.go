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

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("hd init: err=%v resp=%v", err, resp)
	}
	seed, ok := resp.Data["seed"].(string)
	if !ok || len(seed) != 128 {
		t.Fatalf("expected 128-char hex seed, got %q", seed)
	}
	fp := resp.Data["fingerprint"].(string)
	if len(fp) != 8 {
		t.Fatalf("expected 8-char fingerprint, got %q", fp)
	}

	resp, err = b.HandleRequest(ctx, req(logical.ReadOperation, "hd", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("hd read: %v %v", err, resp)
	}
	if resp.Data["fingerprint"] != fp {
		t.Fatalf("fingerprint mismatch")
	}
	if resp.Data["child_count"] != uint32(0) {
		t.Fatalf("expected child_count=0, got %v", resp.Data["child_count"])
	}
}

func TestHD_InitTwiceIsError(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))
	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))
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

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))

	addresses := map[string]bool{}
	for i := 0; i < 5; i++ {
		resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s))
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("derive #%d: err=%v resp=%v", i, err, resp)
		}
		addr := resp.Data["address"].(string)
		if addresses[addr] {
			t.Fatalf("derive #%d: duplicate address %s", i, addr)
		}
		addresses[addr] = true

		if resp.Data["index"] != uint32(i) {
			t.Fatalf("derive #%d: expected index=%d got %v", i, i, resp.Data["index"])
		}
		if !strings.HasPrefix(resp.Data["derivation"].(string), "m/44'/60'/0'/0/") {
			t.Fatalf("unexpected derivation: %s", resp.Data["derivation"])
		}
	}

	resp, _ := b.HandleRequest(ctx, req(logical.ReadOperation, "hd", nil, s))
	if resp.Data["child_count"] != uint32(5) {
		t.Fatalf("expected child_count=5, got %v", resp.Data["child_count"])
	}
}

func TestHD_DeriveExplicitIndex(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum",
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

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))
	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum",
		map[string]interface{}{"name": "hot-hd-0"}, s))

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
	resp, _ := b1.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s1))
	seed := resp.Data["seed"].(string)
	fp1 := resp.Data["fingerprint"].(string)

	for i := 0; i < 3; i++ {
		b1.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s1))
	}
	resp2, _ := b1.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s1))
	addr3 := resp2.Data["address"].(string)

	b2, s2 := newBlockchainBackend(t)
	resp3, err := b2.HandleRequest(ctx, req(logical.UpdateOperation, "hd",
		map[string]interface{}{"seed": seed}, s2))
	if err != nil || (resp3 != nil && resp3.IsError()) {
		t.Fatalf("import seed: err=%v resp=%v", err, resp3)
	}
	if resp3.Data["fingerprint"] != fp1 {
		t.Fatalf("fingerprint mismatch after import: %s vs %s", fp1, resp3.Data["fingerprint"])
	}

	for i := 0; i < 3; i++ {
		b2.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s2))
	}
	resp4, _ := b2.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s2))
	addr3restored := resp4.Data["address"].(string)

	if addr3 != addr3restored {
		t.Fatalf("address mismatch after seed import: original=%s restored=%s", addr3, addr3restored)
	}
}

func TestHD_BitcoinDerivation(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/bitcoin", nil, s))
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

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/solana", nil, s))
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error for solana HD (not supported)")
	}
}

func TestHD_SSS_SplitAndRecover(t *testing.T) {
	ctx := context.Background()

	b1, s1 := newBlockchainBackend(t)
	resp, err := b1.HandleRequest(ctx, req(logical.UpdateOperation, "hd",
		map[string]interface{}{"shares": 5, "threshold": 3}, s1))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("hd init with SSS: err=%v resp=%v", err, resp)
	}

	shards, ok := resp.Data["shards"].([]string)
	if !ok || len(shards) != 5 {
		t.Fatalf("expected 5 shards, got %v", resp.Data["shards"])
	}
	fp1 := resp.Data["fingerprint"].(string)

	b1.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s1))
	deriveResp, _ := b1.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s1))
	addr1 := deriveResp.Data["address"].(string)

	b2, s2 := newBlockchainBackend(t)
	recoverResp, err := b2.HandleRequest(ctx, req(logical.UpdateOperation, "hd/recover",
		map[string]interface{}{"shards": []string{shards[0], shards[2], shards[4]}}, s2))
	if err != nil || (recoverResp != nil && recoverResp.IsError()) {
		t.Fatalf("recover: err=%v resp=%v", err, recoverResp)
	}
	if recoverResp.Data["fingerprint"] != fp1 {
		t.Fatalf("fingerprint mismatch after SSS recover: %s vs %s", fp1, recoverResp.Data["fingerprint"])
	}

	b2.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s2))
	deriveResp2, _ := b2.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum", nil, s2))
	addr1restored := deriveResp2.Data["address"].(string)

	if addr1 != addr1restored {
		t.Fatalf("address mismatch after SSS recover: original=%s restored=%s", addr1, addr1restored)
	}
}

func TestHD_MaxWalletLimit(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "hd", nil, s))

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "hd/derive/ethereum",
		map[string]interface{}{"index": hdMaxWallets}, s))
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error when index exceeds limit")
	}
}

func TestShamir_SplitCombine(t *testing.T) {
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	parts, err := shamirSplit(secret, 5, 3)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	recovered, err := shamirCombine([][]byte{parts[0], parts[2], parts[4]})
	if err != nil {
		t.Fatalf("combine: %v", err)
	}

	for i := range secret {
		if secret[i] != recovered[i] {
			t.Fatalf("byte %d mismatch: want %d got %d", i, secret[i], recovered[i])
		}
	}
}
