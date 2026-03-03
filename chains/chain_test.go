package chains

import (
	"testing"
)

type stubChain struct {
	name string
}

func (s stubChain) Name() string { return s.name }

func (s stubChain) SignRaw(key, hash []byte) ([]byte, error) { return nil, nil }

func (s stubChain) Sign(key, payload []byte) ([]byte, error) { return nil, nil }

func (s stubChain) DeriveAddress(key []byte) (string, error) { return "", nil }

func TestRegister_Get(t *testing.T) {
	c := stubChain{name: "test-chain"}
	Register("test-chain", c)
	defer func() {
		registryMu.Lock()
		delete(registry, "test-chain")
		registryMu.Unlock()
	}()

	got := Get("test-chain")
	if got == nil {
		t.Fatal("get expected non-nil chain")
	}
	if got.Name() != "test-chain" {
		t.Errorf("Name() = %q, want test-chain", got.Name())
	}
} /// if will public, or wrong string format.

func TestGet_unknown(t *testing.T) {
	got := Get("nonexistent-chain-xyz")
	if got != nil {
		t.Errorf("get(unknown) = %v, want nil", got)
	}
}
