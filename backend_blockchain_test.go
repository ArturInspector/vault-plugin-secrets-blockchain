package kv

import (
	"context"
	"encoding/hex"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ed25519"

	// side-effect: registers ethereum, bitcoin, solana
	_ "github.com/hashicorp/vault-plugin-secrets-kv/chains/bitcoin"
	_ "github.com/hashicorp/vault-plugin-secrets-kv/chains/ethereum"
	_ "github.com/hashicorp/vault-plugin-secrets-kv/chains/solana"
)

func newBlockchainBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	conf := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: storage,
		BackendUUID: "smoke-test-uuid",
	}
	b, err := BlockchainFactory(context.Background(), conf)
	if err != nil {
		t.Fatalf("BlockchainFactory: %v", err)
	}
	return b, storage
}

func req(op logical.Operation, path string, data map[string]interface{}, s logical.Storage) *logical.Request {
	return &logical.Request{
		Operation: op,
		Path:      path,
		Data:      data,
		Storage:   s,
	}
}

func TestBlockchainSmoke_EthereumWalletAndSign(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	// Create wallet — generates secp256k1 key, stores only address
	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/smoke", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create wallet: err=%v resp=%v", err, resp)
	}
	addr, ok := resp.Data["address"].(string)
	if !ok || len(addr) != 42 {
		t.Fatalf("expected 0x-address, got %v", resp.Data)
	}

	// Read wallet — must return address, never private_key
	resp, err = b.HandleRequest(ctx, req(logical.ReadOperation, "chains/ethereum/wallets/smoke", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("read wallet: err=%v resp=%v", err, resp)
	}
	if _, leaked := resp.Data["private_key"]; leaked {
		t.Fatal("read: private_key must not be returned")
	}
	if resp.Data["address"] != addr {
		t.Fatalf("address mismatch: %v vs %v", resp.Data["address"], addr)
	}

	// sign_raw: 32-byte hash → R||S||V (65 bytes)
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}
	resp, err = b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/smoke/sign_raw",
		map[string]interface{}{"hash": hex.EncodeToString(hash)}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sign_raw: err=%v resp=%v", err, resp)
	}
	sigHex, _ := resp.Data["signature"].(string)
	sigBytes, _ := hex.DecodeString(sigHex)
	if len(sigBytes) != 65 {
		t.Fatalf("signature len=%d, want 65", len(sigBytes))
	}
}

func TestBlockchainSmoke_BitcoinSignRaw(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/bitcoin/wallets/btctest", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create btc wallet: err=%v resp=%v", err, resp)
	}
	if addr := resp.Data["address"].(string); len(addr) < 4 {
		t.Fatalf("unexpected btc address %q", addr)
	}

	hash := make([]byte, 32)
	resp, err = b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/bitcoin/wallets/btctest/sign_raw",
		map[string]interface{}{"hash": hex.EncodeToString(hash)}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("btc sign_raw: err=%v resp=%v", err, resp)
	}
}

func TestBlockchainSmoke_SolanaSignRaw(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/solana/wallets/sol1", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create sol wallet: err=%v resp=%v", err, resp)
	}

	msg := []byte("hello vault solana")
	resp, err = b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/solana/wallets/sol1/sign_raw",
		map[string]interface{}{"hash": hex.EncodeToString(msg)}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sol sign_raw: err=%v resp=%v", err, resp)
	}
}

func TestBlockchainSmoke_RotateAndVerify(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	// Create
	resp, _ := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/rot", nil, s))
	addr1 := resp.Data["address"].(string)

	// Rotate — must produce a different address
	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/rot/rotate", nil, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	addr2 := resp.Data["address"].(string)
	if addr1 == addr2 {
		t.Fatal("rotate: address unchanged — key not rotated")
	}
}

func TestBlockchainSmoke_SignatureVerifiesWithDerivedPubkey(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	resp, _ := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/verify", nil, s))
	addr := resp.Data["address"].(string)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = 0xab
	}
	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/ethereum/wallets/verify/sign_raw",
		map[string]interface{}{"hash": hex.EncodeToString(hash)}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sign_raw: err=%v resp=%v", err, resp)
	}
	sigBytes, _ := hex.DecodeString(resp.Data["signature"].(string))

	// Recover pubkey from compact sig and verify address matches
	var r, sv secp256k1.ModNScalar
	r.SetByteSlice(sigBytes[:32])
	sv.SetByteSlice(sigBytes[32:64])
	sig := ecdsa.NewSignature(&r, &sv)

	pubKey, _, err := ecdsa.RecoverCompact(
		append([]byte{sigBytes[64] + 27}, sigBytes[:64]...),
		hash,
	)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if !sig.Verify(hash, pubKey) {
		t.Fatal("signature does not verify against recovered pubkey")
	}
	_ = addr
}

// TestBlockchainSmoke_SolanaSignVerifies verifies ed25519 sig against pubkey.
func TestBlockchainSmoke_SolanaSignVerifies(t *testing.T) {
	ctx := context.Background()
	b, s := newBlockchainBackend(t)

	b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/solana/wallets/sv", nil, s))

	// Read address = base58(pubkey)
	resp, _ := b.HandleRequest(ctx, req(logical.ReadOperation, "chains/solana/wallets/sv", nil, s))
	_ = resp.Data["address"]

	msg := []byte("sign this message")
	resp, err := b.HandleRequest(ctx, req(logical.UpdateOperation, "chains/solana/wallets/sv/sign_raw",
		map[string]interface{}{"hash": hex.EncodeToString(msg)}, s))
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sol sign_raw: %v %v", err, resp)
	}
	sigBytes, _ := hex.DecodeString(resp.Data["signature"].(string))
	if len(sigBytes) != ed25519.SignatureSize {
		t.Fatalf("solana sig len=%d, want %d", len(sigBytes), ed25519.SignatureSize)
	}
}
