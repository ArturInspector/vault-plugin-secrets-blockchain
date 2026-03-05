package solana

import (
	"testing"

	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ed25519"
)

func TestDeriveAddress(t *testing.T) {
	c := Chain{}
	seed := bytesRepeat(0x01, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	addr, err := c.DeriveAddress(priv)
	if err != nil {
		t.Fatalf("DeriveAddress: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	want := base58.Encode(pub)
	if addr != want {
		t.Fatalf("address = %s, want %s", addr, want)
	}
}

func TestSignRaw_Verify(t *testing.T) {
	c := Chain{}
	seed := bytesRepeat(0x02, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	msg := []byte("hello solana")

	sig, err := c.SignRaw(priv, msg)
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("len(sig) = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatalf("signature verification failed")
	}
}

func FuzzSignRaw(f *testing.F) {
	c := Chain{}
	seed := bytesRepeat(0x03, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 {
			payload = []byte{0x01}
		}
		sig, err := c.SignRaw(priv, payload)
		if err != nil {
			t.Fatalf("SignRaw: %v", err)
		}
		if !ed25519.Verify(priv.Public().(ed25519.PublicKey), payload, sig) {
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
