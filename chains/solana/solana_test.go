package solana

import (
	"testing"
)

func TestChain_Name(t *testing.T) {
	var c Chain
	if got := c.Name(); got != "solana" {
		t.Errorf("name() %q, want solana", got)
	}
}

func TestChain_SignRaw_returnsError(t *testing.T) {
	var c Chain
	_, err := c.SignRaw([]byte("key"), []byte("hash"))
	if err == nil {
		t.Error("signRaw expected error")
	}
}

func TestChain_Sign_returnsError(t *testing.T) {
	var c Chain
	_, err := c.Sign([]byte("key"), []byte("payload"))
	if err == nil {
		t.Error("Sign: expected error")
	}
}

func TestChain_DeriveAddress_returnsError(t *testing.T) {
	var c Chain
	_, err := c.DeriveAddress([]byte("key"))
	if err == nil {
		t.Error("DeriveAddress: expected error")
	}
}
