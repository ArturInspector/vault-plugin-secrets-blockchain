package chains

var registry = map[string]Chain{}

type Chain interface {
	Name() string

	SignRaw(key []byte, hash []byte) (signature []byte, err error)

	Sign(key []byte, payload []byte) (signed []byte, err error) // todo: btc-eth-sol sign interfaces

	DeriveAddress(key []byte) (address string, err error)
}

type BlockchainSigner interface {
	SignTransaction(tx any) ([]byte, error)
}
