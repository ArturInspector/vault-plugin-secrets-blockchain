package bitcoin

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var btcPrivHex = "4c0883a69102937d6231471b5dbb6204fe512961708279f2c7e3d4a8fa15831e"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestDeriveAddress(t *testing.T) {
	c := Chain{}
	priv := mustHex(t, btcPrivHex)
	addr, err := c.DeriveAddress(priv)
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	if !strings.HasPrefix(addr, "bc1") {
		t.Fatalf("unexpected address %s", addr)
	}
}

func TestSignRaw_Verify(t *testing.T) {
	c := Chain{}
	privBytes := mustHex(t, btcPrivHex)
	hash := bytesRepeat(0x22, 32)

	sig, err := c.SignRaw(privBytes, hash)
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("empty signature")
	}
	sigObj, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		t.Fatalf("ParseDERSignature: %v", err)
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	if !sigObj.Verify(hash, priv.PubKey()) {
		t.Fatalf("verification failed")
	}
}

func FuzzSignRaw(f *testing.F) {
	c := Chain{}
	priv, _ := hex.DecodeString(btcPrivHex)
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, seed []byte) {
		hash := bytesRepeat(0x33, 32)
		copy(hash, seedHash(seed))
		sig, err := c.SignRaw(priv, hash)
		if err != nil {
			t.Fatalf("SignRaw: %v", err)
		}
		sigObj, err := ecdsa.ParseDERSignature(sig)
		if err != nil {
			t.Fatalf("ParseDERSignature: %v", err)
		}
		if !sigObj.Verify(hash, secp256k1.PrivKeyFromBytes(priv).PubKey()) {
			t.Fatalf("verification failed")
		}
	})
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func seedHash(seed []byte) []byte {
	h := make([]byte, 32)
	for i := range seed {
		h[i%32] ^= seed[i]
	}
	return h
}
