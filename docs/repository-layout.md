# What lives in this repository (and what looks like clutter)

This repo is a **fork of HashiCorp’s KV secrets engine** with an added **blockchain signing** engine. Some paths exist for upstream parity; others are optional tools.

## First-class (blockchain plugin)

| Area | Purpose |
|------|---------|
| `cmd/vault-plugin-secrets-blockchain/` | Plugin binary entrypoint (`BlockchainFactory`). |
| `backend_blockchain.go`, `path_wallets.go`, `path_sign.go`, `path_hd.go`, `path_wallet_state.go`, `chains_register.go` | HTTP paths and storage for wallets, sign, HD, freeze. |
| `chains/` | Per-chain crypto (ethereum, bitcoin, solana, tron, …). |
| `backend_blockchain_test.go`, `path_*_test.go` | Tests. |
| `examples/` | Docker, policies. |
| `docs/git-strategy.md` | Conventional Commits, явный `git add`, что не коммитим. |
