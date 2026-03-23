# Policy presets

All examples assume the secrets engine is mounted at **`blockchain`**. If you use another path (e.g. `chains`), replace the prefix in each `.hcl` file or use `sed`.

| File | Role |
|------|------|
| [readonly-addresses.hcl](readonly-addresses.hcl) | List + read addresses only (audit, dashboards). |
| [svc-signer.hcl](svc-signer.hcl) | Backend service: `read` + `sign` / `sign_raw` for wallets named `payment-*`. |
| [escrow-signer.hcl](escrow-signer.hcl) | Same pattern for `escrow-*` wallets only. |
| [ops-admin.hcl](ops-admin.hcl) | Full wallet + HD + freeze + sign (break-glass / platform). |

## Apply

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root   # dev only

vault policy write readonly-addresses examples/policies/readonly-addresses.hcl
vault policy write svc-signer        examples/policies/svc-signer.hcl
vault policy write escrow-signer     examples/policies/escrow-signer.hcl
vault policy write ops-admin         examples/policies/ops-admin.hcl
```

## Automated setup (AppRole + ops-admin + svc-signer)

Шаблон в репозитории: [setup.sh.example](setup.sh.example) — скопируй в `setup.sh` (файл `setup.sh` в `.gitignore`, не обязателен для коммита). Подстрой `PLUGIN_MOUNT`, если mount не `blockchain`.

## Mount path

Policies use paths like `blockchain/chains/ethereum/wallets/...` — that is **`{mount}/{api-path}`** where the plugin exposes `chains/...` under the mount.
