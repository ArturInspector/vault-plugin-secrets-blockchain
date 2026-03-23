package tron

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/hashicorp/vault-plugin-secrets-kv/chains"
	"golang.org/x/crypto/sha3"
)

func (Chain) GenerateKey() ([]byte, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return priv.Serialize(), nil
}

func init() {
	chains.Register("tron", &Chain{})
}

type Chain struct{}

func (Chain) Name() string { return "tron" }

// Tron uses secp256k1 ECDSA — same curve as Ethereum.
// Signature format: R||S||V (65 bytes, recovery id normalized to {0,1}).
func (Chain) SignRaw(key, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hash))
	}
	priv := secp256k1.PrivKeyFromBytes(key)
	sigCompact := ecdsa.SignCompact(priv, hash, false)
	if len(sigCompact) != 65 {
		return nil, fmt.Errorf("unexpected compact signature size %d", len(sigCompact))
	}
	v := sigCompact[0]
	if v < 27 {
		return nil, fmt.Errorf("invalid recovery id %d", v)
	}
	r := sigCompact[1:33]
	s := sigCompact[33:65]
	sig := append(append([]byte{}, r...), s...)
	sig = append(sig, v-27)
	return sig, nil
}

func (c Chain) Sign(key, payload []byte) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload must be 32-byte hash, got %d", len(payload))
	}
	return c.SignRaw(key, payload)
}

// Tron address = Base58Check( 0x41 || keccak256(pubkey[1:])[12:] )
// SLIP-0044 coin type: 195
func (Chain) DeriveAddress(key []byte) (string, error) {
	priv := secp256k1.PrivKeyFromBytes(key)
	pub := priv.PubKey().SerializeUncompressed()

	keccak := sha3.NewLegacyKeccak256()
	keccak.Write(pub[1:]) // drop 0x04 prefix
	pubHash := keccak.Sum(nil)

	// version byte 0x41 = mainnet Tron address
	payload := append([]byte{0x41}, pubHash[12:]...)
	return base58CheckEncode(payload), nil
}

// base58CheckEncode encodes b using Bitcoin Base58Check (double SHA256 checksum).
func base58CheckEncode(b []byte) string {
	checksum := doubleSHA256(b)[:4]
	full := append(b, checksum...)
	return base58Encode(full)
}

func doubleSHA256(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	// count leading zero bytes → leading '1's
	var leadingOnes int
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingOnes++
	}

	// convert big-endian bytes to base58
	digits := make([]byte, 0, len(input)*136/100)
	for _, b := range input {
		carry := int(b)
		for i := 0; i < len(digits); i++ {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}

	result := make([]byte, leadingOnes+len(digits))
	for i := range leadingOnes {
		result[i] = base58Alphabet[0]
	}
	for i, d := range digits {
		result[len(result)-1-i] = base58Alphabet[d]
	}
	return string(result)
}

// AddressToHex converts a Tron Base58 address to its 0x-prefixed hex form.
// Useful for contract calls and ABI encoding.
func AddressToHex(addr string) (string, error) {
	decoded, err := base58CheckDecode(addr)
	if err != nil {
		return "", err
	}
	if len(decoded) != 21 || decoded[0] != 0x41 {
		return "", fmt.Errorf("invalid Tron address")
	}
	return "0x" + hex.EncodeToString(decoded[1:]), nil
}

func base58CheckDecode(s string) ([]byte, error) {
	decoded := base58Decode(s)
	if len(decoded) < 4 {
		return nil, fmt.Errorf("too short")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	expected := doubleSHA256(payload)[:4]
	for i := range 4 {
		if checksum[i] != expected[i] {
			return nil, fmt.Errorf("checksum mismatch")
		}
	}
	return payload, nil
}

func base58Decode(s string) []byte {
	alphabetMap := make(map[byte]int, 58)
	for i := range base58Alphabet {
		alphabetMap[base58Alphabet[i]] = i
	}

	var leadingOnes int
	for _, c := range []byte(s) {
		if c != base58Alphabet[0] {
			break
		}
		leadingOnes++
	}

	digits := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		carry, ok := alphabetMap[c]
		if !ok {
			return nil
		}
		for i := 0; i < len(digits); i++ {
			carry += int(digits[i]) * 58
			digits[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			digits = append(digits, byte(carry&0xff))
			carry >>= 8
		}
	}

	result := make([]byte, leadingOnes+len(digits))
	for i := range len(digits) {
		result[leadingOnes+i] = digits[len(digits)-1-i]
	}
	return result
}
