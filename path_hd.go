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

type hdMasterEntry struct {
	XPrv        string `json:"xprv"`
	Fingerprint string `json:"fingerprint"`
	ChildCount  uint32 `json:"child_count"`
}

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

func pathHD(b *blockchainBackend) []*framework.Path {
	chainField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Chain name (ethereum|bitcoin).",
	}
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("chains/%s/hd$", framework.GenericNameRegex("chain")),
			Fields: map[string]*framework.FieldSchema{
				"chain":    chainField,
				"mnemonic": {Type: framework.TypeString, Description: "64-byte seed as hex (from a previous init). Omit to generate a new one."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleHDInit},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHDInit},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleHDRead},
			},
			HelpSynopsis: "Init or read the HD master key. POST to init (generates seed or imports hex seed). GET to read metadata.",
		},
		{
			Pattern: fmt.Sprintf("chains/%s/hd/derive", framework.GenericNameRegex("chain")),
			Fields: map[string]*framework.FieldSchema{
				"chain": chainField,
				"index": {Type: framework.TypeInt, Description: "BIP44 address_index. Omit to auto-increment."},
				"name":  {Type: framework.TypeString, Description: "Wallet name. Defaults to hd-<index>."},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleHDDerive},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleHDDerive},
			},
			HelpSynopsis: "Derive a child key (BIP44) and store it as a named wallet.",
		},
	}
}

func (b *blockchainBackend) handleHDInit(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName := data.Get("chain").(string)
	if chainName == "" {
		return logical.ErrorResponse("missing chain"), nil
	}
	if _, err := coinTypeForChain(chainName); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	existing, err := b.readHDMaster(ctx, req.Storage, chainName)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return logical.ErrorResponse("HD master already initialized; GET chains/{chain}/hd for metadata"), nil
	}

	var seedBytes []byte
	var seedHex string

	if raw, ok := data.GetOk("mnemonic"); ok {
		imported := strings.TrimSpace(raw.(string))
		decoded, err := hex.DecodeString(imported)
		if err != nil || len(decoded) != 64 {
			return logical.ErrorResponse("mnemonic must be a 64-byte hex-encoded seed"), nil
		}
		seedBytes = decoded
		seedHex = ""
	} else {
		entropy := make([]byte, 32)
		if _, err := rand.Read(entropy); err != nil {
			return nil, fmt.Errorf("entropy: %w", err)
		}
		salt := []byte("vault-signer")
		seedBytes = pbkdf2.Key(entropy, salt, 2048, 64, sha512.New)
		seedHex = hex.EncodeToString(seedBytes)
	}

	master, err := hdkeychain.NewMaster(seedBytes, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}

	xprv, err := master.String()
	if err != nil {
		return nil, err
	}

	pubKey, err := master.ECPubKey()
	if err != nil {
		return nil, err
	}
	h := keccak256bytes(pubKey.SerializeCompressed())
	fingerprint := hex.EncodeToString(h[:4])

	entry := hdMasterEntry{XPrv: xprv, Fingerprint: fingerprint, ChildCount: 0}
	if err := b.writeHDMaster(ctx, req.Storage, chainName, entry); err != nil {
		return nil, err
	}

	resp := map[string]interface{}{
		"fingerprint": fingerprint,
		"child_count": 0,
	}
	if seedHex != "" {
		resp["seed"] = seedHex
	}
	return &logical.Response{Data: resp}, nil
}

func (b *blockchainBackend) handleHDRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	chainName := data.Get("chain").(string)
	if chainName == "" {
		return logical.ErrorResponse("missing chain"), nil
	}
	entry, err := b.readHDMaster(ctx, req.Storage, chainName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return logical.ErrorResponse("HD master not initialized; POST chains/{chain}/hd"), nil
	}
	return &logical.Response{Data: map[string]interface{}{
		"fingerprint": entry.Fingerprint,
		"child_count": entry.ChildCount,
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
		return logical.ErrorResponse("unknown chain"), nil
	}

	masterEntry, err := b.readHDMaster(ctx, req.Storage, chainName)
	if err != nil {
		return nil, err
	}
	if masterEntry == nil {
		return logical.ErrorResponse("HD master not initialized; POST chains/{chain}/hd"), nil
	}

	master, err := hdkeychain.NewKeyFromString(masterEntry.XPrv)
	if err != nil {
		return nil, fmt.Errorf("parse master key: %w", err)
	}

	var childIndex uint32
	if idxRaw, ok := data.GetOk("index"); ok {
		v, ok := idxRaw.(int)
		if !ok || v < 0 {
			return logical.ErrorResponse("index must be a non-negative integer"), nil
		}
		childIndex = uint32(v)
	} else {
		childIndex = masterEntry.ChildCount
	}

	name := fmt.Sprintf("hd-%d", childIndex)
	if nameRaw, ok := data.GetOk("name"); ok {
		if s, ok := nameRaw.(string); ok && s != "" {
			name = s
		}
	}

	exists, err := b.walletExists(ctx, req.Storage, chainName, name)
	if err != nil {
		return nil, err
	}
	if exists {
		return logical.ErrorResponse("wallet %q already exists", name), nil
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

	we := walletEntry{PrivateKey: hex.EncodeToString(keyBytes), Address: addr}
	if err := b.writeWallet(ctx, req.Storage, chainName, name, we); err != nil {
		return nil, err
	}

	if childIndex >= masterEntry.ChildCount {
		masterEntry.ChildCount = childIndex + 1
		if err := b.writeHDMaster(ctx, req.Storage, chainName, *masterEntry); err != nil {
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

func (b *blockchainBackend) hdMasterKey(chainName string) string {
	return path.Join(b.storagePrefix, "hd", chainName, "master")
}

func (b *blockchainBackend) readHDMaster(ctx context.Context, s logical.Storage, chainName string) (*hdMasterEntry, error) {
	raw, err := s.Get(ctx, b.hdMasterKey(chainName))
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

func (b *blockchainBackend) writeHDMaster(ctx context.Context, s logical.Storage, chainName string, entry hdMasterEntry) error {
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.Put(ctx, &logical.StorageEntry{
		Key:   b.hdMasterKey(chainName),
		Value: payload,
	})
}

func keccak256bytes(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
