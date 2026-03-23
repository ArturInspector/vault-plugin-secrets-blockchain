# Examples — fastest path to a working demo

## 1. Build the plugin

From the **repository root**:

```bash
./examples/build-plugin.sh
```

This writes `examples/plugin/vault-plugin-secrets-blockchain`.

## 2. Run Vault (dev)

```bash
cd examples
docker compose up -d
```

Vault listens on `http://127.0.0.1:8200`, root token `root`.

## 3. Register and mount the engine

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

SHA=$(sha256sum examples/plugin/vault-plugin-secrets-blockchain | awk '{print $1}')
vault plugin register -sha256="$SHA" secret vault-plugin-secrets-blockchain
vault secrets enable -path=blockchain -plugin-name=vault-plugin-secrets-blockchain plugin
```

## 4. Policies

See [policies/README.md](policies/README.md). Quick apply:

```bash
vault policy write ops-admin examples/policies/ops-admin.hcl
```

Create a token with that policy for interactive tests, or copy [policies/setup.sh.example](policies/setup.sh.example) to `policies/setup.sh` for AppRole + `svc-signer` (локальный скрипт, в git не трекается).

## 5. First wallet and signature

```bash
vault write blockchain/chains/ethereum/wallets/demo chain=ethereum name=demo
vault read  blockchain/chains/ethereum/wallets/demo
vault write blockchain/chains/ethereum/wallets/demo/sign_raw \
  chain=ethereum name=demo \
  hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

(Use a real 32-byte hex hash for production; the line above is length-check only.)

## Other samples

- [payment-service/](payment-service/) — Go sample calling Vault for signing (adjust module path if you fork).
- [k8s/](k8s/) — minimal Deployment/Service sketch.
- [Dockerfile.plugin](Dockerfile.plugin) — build only the binary in OCI for CI.

For GIF / asciinema, record steps 3–5 in one terminal session.
