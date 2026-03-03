package bitcoin

import (
	"testing"
)

func TestChain_Name(t *testing.T) {
	var c Chain
	if got := c.Name(); got != "bitcoin" {
		t.Errorf("Name() = %q, want bitcoin", got)
	}
}

func TestChain_SignRaw_returnsError(t *testing.T) {
	var c Chain
	_, err := c.SignRaw([]byte("key"), []byte("hash"))
	if err == nil {
		t.Error("SignRaw: expected error")
	}
	if err != nil && err.Error() != "bitcoin: not implemented" {
		t.Errorf("SignRaw err = %v", err)
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
