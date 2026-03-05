package ethereum

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var (
	testPrivHex = "4c0883a69102937d6231471b5dbb6204fe512961708279f2c7e3d4a8fa15831e" // common dev key
	testAddr    = "0x8ff2c0b1915fe7c6c6ce001014d18d82b054dbff"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func TestDeriveAddress(t *testing.T) {
	c := Chain{}
	key := mustDecodeHex(t, testPrivHex)
	addr, err := c.DeriveAddress(key)
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	if addr != testAddr {
		t.Fatalf("DeriveAddress = %s, want %s", addr, testAddr)
	}
}

func TestSignRaw_DeterministicAndVerifies(t *testing.T) {
	c := Chain{}
	key := mustDecodeHex(t, testPrivHex)
	hash := bytesRepeat(0x11, 32)

	sig1, err := c.SignRaw(key, hash)
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}
	sig2, err := c.SignRaw(key, hash)
	if err != nil {
		t.Fatalf("SignRaw2: %v", err)
	}
	if len(sig1) != 65 {
		t.Fatalf("signature len = %d, want 65", len(sig1))
	}
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Fatalf("SignRaw not deterministic")
	}

	sigRS := sig1[:64]
	v := sig1[64]
	if v > 3 {
		t.Fatalf("unexpected recovery id %d", v)
	}
	sigObj := parseSignatureRS(sigRS)
	priv := secp256k1.PrivKeyFromBytes(key)
	if !sigObj.Verify(hash, priv.PubKey()) {
		t.Fatalf("signature failed verification")
	}
}

func FuzzSignRaw(f *testing.F) {
	c := Chain{}
	key, _ := hex.DecodeString(testPrivHex)
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, seed []byte) {
		hash := bytesRepeat(0xaa, 32)
		if len(seed) > 0 {
			copy(hash, seedHash(seed))
		}
		sig, err := c.SignRaw(key, hash)
		if err != nil {
			t.Fatalf("SignRaw: %v", err)
		}
		if len(sig) != 65 {
			t.Fatalf("signature len = %d, want 65", len(sig))
		}
		sigObj := parseSignatureRS(sig[:64])
		priv := secp256k1.PrivKeyFromBytes(key)
		if !sigObj.Verify(hash, priv.PubKey()) {
			t.Fatalf("verify failed")
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

func parseSignatureRS(rs []byte) *ecdsa.Signature {
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(rs[:32])
	s.SetByteSlice(rs[32:])
	return ecdsa.NewSignature(&r, &s)
}
