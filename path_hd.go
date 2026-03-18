package kv

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

const (
	hdGlobalChain = "global"
	hdMaxWallets  = 200
)

type hdMasterEntry struct {
	XPrv        string `json:"xprv"`
	Fingerprint string `json:"fingerprint"`
	ChildCount  uint32 `json:"child_count"`
}

// coinTypeForChain returns the BIP44 coin type for the given chain.
// Standard: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
func coinTypeForChain(chainName string) (uint32, error) {
	switch chainName {
	case "ethereum":
		return 60, nil
	case "bitcoin":
		return 0, nil
	default:
		return 0, fmt.Errorf("HD derivation not supported for chain %q", chainName)
	}
}

// deriveBIP44 derives a child key by path m/44'/coinType'/0'/0/index.
// Hardened levels (') protect against child key compromise.
func deriveBIP44(master *hdkeychain.ExtendedKey, coinType, index uint32) (*hdkeychain.ExtendedKey, error) {
	levels := []uint32{
		44 + hdkeychain.HardenedKeyStart,
		coinType + hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
		0,
		index,
	}
	key := master
	for _, level := range levels {
		child, err := key.Derive(level)
		if err != nil {
			return nil, err
		}
		key = child
	}
	return key, nil
}

// splitSeedIfRequested splits the seed into shards using Shamir Secret Sharing.
// Returns nil if shares == 0 (SSS not requested).
// Shards are ephemeral — only returned in API response, not stored.
func splitSeedIfRequested(seed []byte, shares, threshold int) ([]string, error) {
	if shares == 0 {
		return nil, nil
	}
	if threshold < 2 || threshold > shares {
		return nil, fmt.Errorf("threshold must be >= 2 and <= shares (%d)", shares)
	}
	if shares > 255 {
		return nil, fmt.Errorf("shares must be <= 255")
	}

	parts, err := shamirSplit(seed, shares, threshold)
	if err != nil {
		return nil, fmt.Errorf("shamir split: %w", err)
	}

	hexParts := make([]string, len(parts))
	for i, p := range parts {
		hexParts[i] = hex.EncodeToString(p)
	}
	return hexParts, nil
}

func pathHD(b *blockchainBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "hd$",
			Fields: map[string]*framework.FieldSchema{
				"seed":      {Type: framework.TypeString, Description: "64-byte hex seed for import. If omitted, a new seed is generated."},
				"shares":    {Type: framework.TypeInt, Description: "Number of SSS shards (2–255). 0 = no SSS."},
				"threshold": {Type: framework.TypeInt, Description: "Minimum shards for recovery. Required if shares > 0."},
			},
			ExistenceCheck: b.handleHDMasterExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleHDInit},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHDInit},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleHDRead},
			},
			HelpSynopsis: "Initialize global HD master seed. POST create/import. GET metadata.",
		},
		{
			Pattern: "hd/recover$",
			Fields: map[string]*framework.FieldSchema{
				"shards": {Type: framework.TypeStringSlice, Description: "List of hex shards to recover the seed."},
			},
			ExistenceCheck: func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (bool, error) {
				return false, nil
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleHDRecover},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHDRecover},
			},
			HelpSynopsis: "Recover HD master seed from SSS shards.",
		},
		{
			Pattern: fmt.Sprintf("hd/derive/%s", framework.GenericNameRegex("chain")),
			Fields: map[string]*framework.FieldSchema{
				"chain": {Type: framework.TypeString, Description: "Chain: ethereum | bitcoin."},
				"index": {Type: framework.TypeInt, Description: "BIP44 address_index. If omitted — auto-increment."},
				"name":  {Type: framework.TypeString, Description: "Wallet name. Defaults to hd-{chain}-{index}."},
			},
			ExistenceCheck: func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (bool, error) {
				return false, nil
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleHDDerive},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHDDerive},
			},
			HelpSynopsis: "Derive a child key from the global HD seed and save as a named wallet.",
		},
	}
}

func (b *blockchainBackend) handleHDInit(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	existing, err := b.readHDMaster(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("HD master already initialized; use GET hd for metadata"), nil
	}

	seedBytes, returnSeedHex, err := resolveSeed(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	master, fingerprint, err := masterFromSeed(seedBytes)
	if err != nil {
		return nil, err
	}

	entry := hdMasterEntry{XPrv: master.String(), Fingerprint: fingerprint, ChildCount: 0}
	if err := b.writeHDMaster(ctx, req.Storage, entry); err != nil {
		return nil, err
	}

	resp := map[string]interface{}{
		"fingerprint": fingerprint,
		"child_count": 0,
	}
	if returnSeedHex != "" {
		resp["seed"] = returnSeedHex
	}

	shares, _ := data.Get("shares").(int)
	threshold, _ := data.Get("threshold").(int)
	shards, err := splitSeedIfRequested(seedBytes, shares, threshold)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if shards != nil {
		resp["shards"] = shards
		resp["threshold"] = threshold
	}

	return &logical.Response{Data: resp}, nil
}

func (b *blockchainBackend) handleHDRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entry, err := b.readHDMaster(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("HD master not initialized; POST hd"), nil
	}
	return &logical.Response{Data: map[string]interface{}{
		"fingerprint": entry.Fingerprint,
		"child_count": entry.ChildCount,
	}}, nil
}

func (b *blockchainBackend) handleHDRecover(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	existing, err := b.readHDMaster(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("HD master already exists; delete it first"), nil
	}

	rawShards, ok := data.GetOk("shards")
	if !ok {
		return logical.ErrorResponse("shards is required"), nil
	}
	shardStrs, ok := rawShards.([]string)
	if !ok || len(shardStrs) < 2 {
		return logical.ErrorResponse("at least 2 shards are required"), nil
	}

	shardBytes := make([][]byte, len(shardStrs))
	for i, s := range shardStrs {
		b, err := hex.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("shard %d: invalid hex", i)), nil
		}
		shardBytes[i] = b
	}

	seedBytes, err := shamirCombine(shardBytes)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to recover seed: %v", err)), nil
	}
	if len(seedBytes) != 64 {
		return logical.ErrorResponse("recovered seed must be 64 bytes"), nil
	}

	master, fingerprint, err := masterFromSeed(seedBytes)
	if err != nil {
		return nil, err
	}

	entry := hdMasterEntry{XPrv: master.String(), Fingerprint: fingerprint, ChildCount: 0}
	if err := b.writeHDMaster(ctx, req.Storage, entry); err != nil {
		return nil, err
	}

	return &logical.Response{Data: map[string]interface{}{
		"fingerprint": fingerprint,
		"recovered":   true,
	}}, nil
}

func (b *blockchainBackend) handleHDDerive(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName := data.Get("chain").(string)
	if chainName == "" {
		return logical.ErrorResponse("missing chain"), nil
	}

	coinType, err := coinTypeForChain(chainName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	chain := chains.Get(chainName)
	if chain == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown chain: %s", chainName)), nil
	}

	masterEntry, err := b.readHDMaster(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if masterEntry == nil {
		return logical.ErrorResponse("HD master not initialized; POST hd"), nil
	}

	if masterEntry.ChildCount >= hdMaxWallets {
		return logical.ErrorResponse(fmt.Sprintf("wallet limit of %d reached", hdMaxWallets)), nil
	}

	master, err := hdkeychain.NewKeyFromString(masterEntry.XPrv)
	if err != nil {
		return nil, fmt.Errorf("parse master key: %w", err)
	}

	childIndex, err := resolveChildIndex(data, masterEntry.ChildCount)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name := resolveWalletName(data, chainName, childIndex)

	exists, err := b.walletExists(ctx, req.Storage, chainName, name)
	if err != nil {
		return nil, err
	}
	if exists {
		return logical.ErrorResponse(fmt.Sprintf("wallet %q already exists", name)), nil
	}

	child, err := deriveBIP44(master, coinType, childIndex)
	if err != nil {
		return nil, fmt.Errorf("derive m/44'/%d'/0'/0/%d: %w", coinType, childIndex, err)
	}

	privKey, err := child.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("extract private key: %w", err)
	}
	keyBytes := privKey.Serialize()

	addr, err := chain.DeriveAddress(keyBytes)
	if err != nil {
		return nil, err
	}

	if err := b.writeWallet(ctx, req.Storage, chainName, name, walletEntry{
		PrivateKey: hex.EncodeToString(keyBytes),
		Address:    addr,
	}); err != nil {
		return nil, err
	}

	if childIndex >= masterEntry.ChildCount {
		masterEntry.ChildCount = childIndex + 1
		if err := b.writeHDMaster(ctx, req.Storage, *masterEntry); err != nil {
			return nil, err
		}
	}

	return &logical.Response{Data: map[string]interface{}{
		"name":        name,
		"address":     addr,
		"index":       childIndex,
		"derivation":  fmt.Sprintf("m/44'/%d'/0'/0/%d", coinType, childIndex),
		"fingerprint": masterEntry.Fingerprint,
	}}, nil
}

// --- storage helpers ---

func (b *blockchainBackend) hdMasterKey() string {
	return path.Join(b.storagePrefix, "hd", hdGlobalChain, "master")
}

func (b *blockchainBackend) readHDMaster(ctx context.Context, s logical.Storage) (*hdMasterEntry, error) {
	raw, err := s.Get(ctx, b.hdMasterKey())
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var entry hdMasterEntry
	if err := raw.DecodeJSON(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (b *blockchainBackend) writeHDMaster(ctx context.Context, s logical.Storage, entry hdMasterEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{
		Key:   b.hdMasterKey(),
		Value: payload,
	})
}

func (b *blockchainBackend) handleHDMasterExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	entry, err := b.readHDMaster(ctx, req.Storage)
	return entry != nil, err
}

// --- pure helper functions (no side effects, easy to test) ---

// resolveSeed returns the seed bytes and hex for response (hex is empty if imported).
func resolveSeed(data *framework.FieldData) ([]byte, string, error) {
	if raw, ok := data.GetOk("seed"); ok {
		imported := strings.TrimSpace(raw.(string))
		decoded, err := hex.DecodeString(imported)
		if err != nil || len(decoded) != 64 {
			return nil, "", fmt.Errorf("seed must be 64 bytes hex")
		}
		return decoded, "", nil
	}

	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return nil, "", fmt.Errorf("entropy: %w", err)
	}
	seedBytes := pbkdf2.Key(entropy, []byte("vault-signer"), 2048, 64, sha512.New)
	return seedBytes, hex.EncodeToString(seedBytes), nil
}

// masterFromSeed создаёт master extended key и fingerprint из seed bytes.
func masterFromSeed(seedBytes []byte) (*hdkeychain.ExtendedKey, string, error) {
	master, err := hdkeychain.NewMaster(seedBytes, &chaincfg.MainNetParams)
	if err != nil {
		return nil, "", fmt.Errorf("master key: %w", err)
	}
	pubKey, err := master.ECPubKey()
	if err != nil {
		return nil, "", err
	}
	h := keccak256bytes(pubKey.SerializeCompressed())
	return master, hex.EncodeToString(h[:4]), nil
}

// resolveChildIndex determines the child key index.
func resolveChildIndex(data *framework.FieldData, autoNext uint32) (uint32, error) {
	if idxRaw, ok := data.GetOk("index"); ok {
		v, ok := idxRaw.(int)
		if !ok || v < 0 {
			return 0, fmt.Errorf("index must be a non-negative integer")
		}
		if uint32(v) >= hdMaxWallets {
			return 0, fmt.Errorf("index cannot exceed %d", hdMaxWallets-1)
		}
		return uint32(v), nil
	}
	return autoNext, nil
}

func resolveWalletName(data *framework.FieldData, chainName string, index uint32) string {
	if nameRaw, ok := data.GetOk("name"); ok {
		if s, ok := nameRaw.(string); ok && s != "" {
			return s
		}
	}
	return fmt.Sprintf("hd-%s-%d", chainName, index)
}

func keccak256bytes(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
