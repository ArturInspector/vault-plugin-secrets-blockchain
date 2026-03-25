# vsigner (Go)

CLI для Vault **blockchain** secrets engine из этого репозитория.

## Быстрый старт (~2 мин после монтирования плагина)

```bash
cd cmd/vsigner && go build -o vsigner .
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root   # нужны права на sys/policy (root или sudo)
./vsigner quickstart
./vsigner preset apply demo    # только ops-admin; или: preset apply full
./vsigner status
```

- **`preset apply`** подставляет `VAULT_MOUNT` вместо префикса `blockchain/` во встроенных HCL.
- **`preset apply --dry-run`** — показать политики без Vault (без токена).

## Команды

| Команда | Назначение |
|---------|------------|
| `quickstart` | Текст шагов: env → preset → первый кошелёк |
| `preset list` | Бандлы `demo`, `full`, `payments`, `escrow` и отдельные политики |
| `preset apply <name>` | Залить ACL одним вызовом |
| `status` / `list` | Health + таблица кошельков по чейнам |
| `hd`, `wallet` | HD и кошельки |
| `audit --summary` | Дашборд по audit-файлу; `--log` или `VAULT_AUDIT_LOG` |

### Audit

```bash
export VAULT_AUDIT_LOG=/var/log/vault/audit.log   # или копия файла
./vsigner audit --summary
./vsigner audit --log ./audit.log --summary
```

Полная таблица событий: `./vsigner audit --log ./audit.log` (без `--summary`).

## Сборка без конфликта имени `vsigner`

См. [install.sh](install.sh) → `~/.local/bin/vsigner-vault`.

## «No help topic for 'list'»

В PATH может быть **другой** бинарник. Проверка: `./vsigner --version` (ожидается **0.3.x**).
