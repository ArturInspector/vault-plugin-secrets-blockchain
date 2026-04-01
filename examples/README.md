# Examples — fastest path to a working demo

## 1. Build the plugin

From the **repository root**:

```bash
./examples/build-plugin.sh
```

This writes `examples/plugin/vault-plugin-secrets-blockchain`.

**Важно:** в каталоге `examples/plugin/` при работе через Docker должен быть **только** собранный бинарник. Любые другие файлы (например `.gitkeep`, `README`) ломают Vault dev: он пытается загрузить их как плагины и падает.

## 2. Run Vault (dev)

```bash
cd examples
docker compose up -d
```

Vault listens on `http://127.0.0.1:8200`, root token `root`.

## 3. Register and mount the engine

Сначала должен существовать бинарник из шага 1. Пути ниже — **два варианта**, в зависимости от текущей директории.

### Из **корня** репозитория (`vault-plugin-secrets-blockchain/`)

**bash / zsh:**

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root

SHA=$(sha256sum examples/plugin/vault-plugin-secrets-blockchain | awk '{print $1}')
vault plugin register -sha256="$SHA" secret vault-plugin-secrets-blockchain
vault secrets enable -path=blockchain -plugin-name=vault-plugin-secrets-blockchain plugin
```

**fish:**

```fish
set -x VAULT_ADDR http://127.0.0.1:8200
set -x VAULT_TOKEN root

set SHA (sha256sum examples/plugin/vault-plugin-secrets-blockchain | awk '{print $1}')
vault plugin register -sha256=$SHA secret vault-plugin-secrets-blockchain
vault secrets enable -path=blockchain -plugin-name=vault-plugin-secrets-blockchain plugin
```

### Из каталога **`examples/`** (после `cd examples`)

Используй **`plugin/...`**, не `examples/plugin/...`:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
SHA=$(sha256sum plugin/vault-plugin-secrets-blockchain | awk '{print $1}')
vault plugin register -sha256="$SHA" secret vault-plugin-secrets-blockchain
vault secrets enable -path=blockchain -plugin-name=vault-plugin-secrets-blockchain plugin
```

```fish
set -x VAULT_ADDR http://127.0.0.1:8200
set -x VAULT_TOKEN root
set SHA (sha256sum plugin/vault-plugin-secrets-blockchain | awk '{print $1}')
vault plugin register -sha256=$SHA secret vault-plugin-secrets-blockchain
vault secrets enable -path=blockchain -plugin-name=vault-plugin-secrets-blockchain plugin
```

### Если `path is already in use at blockchain/`

Значит движок уже смонтирован (например после прошлой попытки). Проверка: `vault secrets list`. Обычно **ничего делать не нужно** — переходи к шагу 4. Чтобы пересоздать mount с нуля: `vault secrets disable blockchain/`, затем снова `vault secrets enable ...` (после успешного `vault plugin register`).

## 4. Policies (~2 minutes with CLI)

**Fast path:** from repo root, with `vsigner` built (`cd cmd/vsigner && go build -o vsigner .`):

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
# VAULT_MOUNT must match your engine mount (default blockchain)

./cmd/vsigner/vsigner quickstart          # prints env + next steps
./cmd/vsigner/vsigner preset list        # bundles: demo | full | payments | escrow
./cmd/vsigner/vsigner preset apply --dry-run demo   # preview HCL (no Vault needed)
./cmd/vsigner/vsigner preset apply demo             # uploads ops-admin ACL (token needs policy write)
```

`preset apply` embeds the same rules as [policies/](policies/) and rewrites the mount prefix from `VAULT_MOUNT`.

**Manual path:** see [policies/README.md](policies/README.md). Example (из **корня** репо):

```bash
vault policy write ops-admin examples/policies/ops-admin.hcl
```

Если ты в **`examples/`**: `vault policy write ops-admin policies/ops-admin.hcl`.

AppRole + `svc-signer`: copy [policies/setup.sh.example](policies/setup.sh.example) to `policies/setup.sh` (локальный скрипт, в git не трекается).

### Audit log (optional)

Point the CLI at a **file** copy of Vault’s audit log, then one-shot summary:

```bash
export VAULT_AUDIT_LOG=/path/to/audit.log
./cmd/vsigner/vsigner audit --summary
# or: ./cmd/vsigner/vsigner audit --log /path/to/audit.log --summary
```

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
