package chains

import "sync"

var (
	registry   = map[string]Chain{} // todo: one register
	registryMu sync.RWMutex
)

func Register(name string, c Chain) { // call from chain package init
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = c
}

func Get(name string) Chain {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[name]
}

type Chain interface {
	Name() string

	GenerateKey() ([]byte, error)

	SignRaw(key []byte, hash []byte) (signature []byte, err error)

	Sign(key []byte, payload []byte) (signed []byte, err error)

	DeriveAddress(key []byte) (address string, err error)
}

// optional higher-level interface for transaction signing
// Chain.Sign is the primary contract; implement this where a single tx object is preferred.
type BlockchainSigner interface {
	SignTransaction(tx any) ([]byte, error)
}
