package tron

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveAddress_Format(t *testing.T) {
	// known private key → expected Tron address (T-prefix, 34 chars)
	// generated with: tronweb.utils.crypto
	privHex := "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
	privKey, _ := hex.DecodeString(privHex)

	c := Chain{}
	addr, err := c.DeriveAddress(privKey)
	if err != nil {
		t.Fatalf("DeriveAddress error: %v", err)
	}

	if !strings.HasPrefix(addr, "T") {
		t.Errorf("Tron address must start with T, got: %s", addr)
	}
	if len(addr) != 34 {
		t.Errorf("Tron address must be 34 chars, got: %d (%s)", len(addr), addr)
	}
}

func TestBase58CheckRoundtrip(t *testing.T) {
	payload := []byte{0x41, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	encoded := base58CheckEncode(payload)
	decoded, err := base58CheckDecode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if string(decoded) != string(payload) {
		t.Errorf("roundtrip mismatch: got %x, want %x", decoded, payload)
	}
}

func TestAddressToHex(t *testing.T) {
	privHex := "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
	privKey, _ := hex.DecodeString(privHex)

	c := Chain{}
	addr, _ := c.DeriveAddress(privKey)

	hexAddr, err := AddressToHex(addr)
	if err != nil {
		t.Fatalf("AddressToHex error: %v", err)
	}

	if !strings.HasPrefix(hexAddr, "0x") {
		t.Errorf("hex address must start with 0x, got: %s", hexAddr)
	}
	if len(hexAddr) != 42 {
		t.Errorf("hex address must be 42 chars (0x + 20 bytes), got: %d", len(hexAddr))
	}
}

func TestSignRaw(t *testing.T) {
	privHex := "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
	privKey, _ := hex.DecodeString(privHex)
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}

	c := Chain{}
	sig, err := c.SignRaw(privKey, hash)
	if err != nil {
		t.Fatalf("SignRaw error: %v", err)
	}
	if len(sig) != 65 {
		t.Errorf("signature must be 65 bytes, got %d", len(sig))
	}
	// V must be 0 or 1
	if sig[64] > 1 {
		t.Errorf("V byte must be 0 or 1, got %d", sig[64])
	}
}
