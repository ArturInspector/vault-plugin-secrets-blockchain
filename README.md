# vault-plugin-secrets-blockchain

## You have a product. Now where do the keys live?

Sooner or later you need to decide where to keep **company wallet keys**—not personal seed phrases in a notes app, but whatever will sign payouts, escrow releases, and refunds.

You look around. **Fireblocks** and similar platforms are strong, but for many teams they mean another vendor contract, a long onboarding, and a price you still have to justify. **MPC** and custodial stacks are a discipline of their own: not “plug and play,” but a multi-month project. **AWS KMS** is not in the same box either: there is no first-class **secp256k1** story the way Ethereum and many Bitcoin flows expect.

So the honest options are: **build it yourself**—your own storage service, your own signing pipeline, your own risk on every line—or lean on something your stack already runs.

**There is another way.** [HashiCorp Vault](https://www.vaultproject.io/) already gives you policy, audit, and storage. People have asked for **secp256k1** signing in **Transit** for a long time (without it, “Ethereum as people integrate it” does not map cleanly onto the engine everyone wishes for). The conversation ran for years—for example issue [#4594](https://github.com/hashicorp/vault/issues/4594) (*Transit engine ecdsa-secp256k1 support*, opened in 2018, **23 👍** from the community). There were attempts to land it in core—see [PR #11469](https://github.com/hashicorp/vault/pull/11469) and [PR #12685](https://github.com/hashicorp/vault/pull/12685). In 2022 the issue was closed with a clear line: **built-in Transit is not planned to add this in the foreseeable future**, and Vault is open source—fork it or build **plugins** for what you need. Since then, plugins have been the natural home for blockchain-shaped secp256k1 without fighting core’s priorities.

This repository is a **practical answer from that thread**: a standalone secrets engine plugin that attaches to Vault as the place where the key lives and where signing runs—not inside your microservice. We are not “instead of HashiCorp”—we sit **beside** it: same Vault, same policies, same logs.

**Thank you to the HashiCorp team** for Vault and the plugin ecosystem. **Thank you** as well to everyone who kept raising secp256k1 in issues and PRs—without that noise we would not have such a clear picture of what operators want from infrastructure. We continue that line in open code: not claiming to be the one size for everyone, but giving teams a path where the private key never has to sit in application memory.

This plugin signs for **Ethereum, Bitcoin, and Solana** so your app **never holds the private key**. If you have ever done `read secret → sign in process`, you already know the failure mode; here, signing happens **inside Vault**. We are not pretending to be Fireblocks or an HSM—only a serious step up from “key in env,” using Vault’s policies and audit trail.

---

## What you get

- **Keys stay in Vault’s storage** (encrypted at rest; use seal wrap and production hardening for anything that touches real funds).
- **One place for policy**: who may create wallets, who may sign, which paths—standard Vault policies, not a second auth system.
- **Audit trail**: signing requests go through Vault’s audit log, alongside the rest of your infrastructure secrets.
- **Chains today**: `ethereum`, `bitcoin`, `solana`—each behind the same idea: implement `chains.Chain`, register once, route from HTTP paths.

Rough flow in words: your service builds the transaction (or the hash you need signed), calls Vault, receives a signature. Broadcasting, indexing, and business rules stay **your** code—on purpose, so you are not locked into our idea of “what a transaction is”.

---

## What this is not

- **Not a wallet product** for end users (no balances, no block explorer inside Vault).
- **Not a replacement for an HSM** when your threat model requires physical key isolation.
- **Not a shortcut around Vault operations**: unsealed Vault, token hygiene, network TLS, and backup strategy still matter.

The [IDEA.md](IDEA.md) file describes the longer-term vision (governance, tiers, landing page). This README stays close to what the plugin does **today**.

---

## Interface (HTTP / Vault API)

Mount the plugin at a path you choose (examples below use **`blockchain`**). All API paths are relative to that mount: `{mount}/chains/...`.

| What you need | Method | Path (under mount) |
|---------------|--------|---------------------|
| Create a wallet (generates a key inside Vault) | `POST` | `chains/:chain/wallets/:name` |
| Import an existing private key (hex) | `POST` | `chains/:chain/wallets/:name/import` |
| Read address only (never the private key) | `GET` | `chains/:chain/wallets/:name` |
| Delete wallet | `DELETE` | `chains/:chain/wallets/:name` |
| Rotate key | `POST` | `chains/:chain/wallets/:name/rotate` |
| List wallet names | `LIST` | `chains/:chain/wallets/` |
| Sign a payload (chain-specific; often a 32-byte hash as hex for ETH/BTC) | `POST` | `chains/:chain/wallets/:name/sign` |
| Sign a raw message / hash (hex body field `hash`) | `POST` | `chains/:chain/wallets/:name/sign_raw` |

`chain` is one of: `ethereum`, `bitcoin`, `solana`.

Details of signature encoding (e.g. Ethereum `R||S||V`, Bitcoin DER, Solana ed25519) live in the `chains/` packages—read there before integrating, so your broadcaster matches what you verify on-chain.

---

## Quick start (Docker + demo flow)

Step-by-step (build script, `docker compose`, register, first `vault write`) is in **[examples/README.md](examples/README.md)**. That is the path we recommend for a **GIF or asciinema** (one terminal, steps 3–5).

Shorthand from repo root:

```sh
./examples/build-plugin.sh
cd examples && docker compose up -d
# then register + enable — see examples/README.md
```

---

## Policy presets

Ready-made Vault ACLs (replace the `blockchain` prefix if your mount differs):

| Preset | File |
|--------|------|
| Read-only addresses (audit / dashboards) | [examples/policies/readonly-addresses.hcl](examples/policies/readonly-addresses.hcl) |
| Backend signer (`payment-*` wallets) | [examples/policies/svc-signer.hcl](examples/policies/svc-signer.hcl) |
| Escrow-only signer (`escrow-*` wallets) | [examples/policies/escrow-signer.hcl](examples/policies/escrow-signer.hcl) |
| Platform admin (wallets + HD + freeze + sign) | [examples/policies/ops-admin.hcl](examples/policies/ops-admin.hcl) |

Details and `vault policy write ...` commands: **[examples/policies/README.md](examples/policies/README.md)**. Optional **AppRole** bootstrap: copy [examples/policies/setup.sh.example](examples/policies/setup.sh.example) to a local `setup.sh` (see [.gitignore](.gitignore)). Git workflow: **[docs/git-strategy.md](docs/git-strategy.md)**.

OCI image that only builds the plugin binary (for CI): [examples/Dockerfile.plugin](examples/Dockerfile.plugin).

Kubernetes samples: [examples/k8s/](examples/k8s/).

---

## This repository

This project started from HashiCorp’s **KV** plugin (`vault-plugin-secrets-kv`). The **blockchain** engine is a separate binary: `cmd/vault-plugin-secrets-blockchain` and `BlockchainFactory` in code. The classic KV engine remains in-tree for upstream alignment and contribution; enable whichever engine your deployment needs.

**What is “extra” in the tree?** See **[docs/repository-layout.md](docs/repository-layout.md)** (upstream KV files, optional CLIs, what should never be committed).

---

## Development

Requirements: Go (see [.go-version](.go-version)).

```sh
go test ./...
go vet ./...
```

CI runs `go build ./...`, `go test ./...`, and `go vet ./...` on push and pull requests.

Upstream KV development flows (e.g. `make dev`, `make test`) still apply to the KV plugin path; for the blockchain plugin, `go build` / `go test` as above are enough for day-to-day work.

---

## Security

If you think you found a vulnerability in **this fork’s** blockchain signing code, please report responsibly (open a private security advisory on the repository or contact the maintainers you trust). For issues in **HashiCorp Vault core**, use HashiCorp’s process: [security@hashicorp.com](mailto:security@hashicorp.com).

---

## Visuals and site

Screenshots, GIFs, and a dedicated landing page will be added separately so this file stays easy to read in a terminal and in git. When they exist, we will link them here.

---

## License

See repository license files. Upstream KV portions retain their original SPDX headers where applicable.
