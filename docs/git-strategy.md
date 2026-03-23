# Git: что коммитить и как

## Conventional Commits

Формат: `<type>(<scope>): <краткое описание>`

| Type | Когда |
|------|--------|
| `feat` | новая возможность (API, команда, путь Vault) |
| `fix` | исправление бага |
| `docs` | только документация / README |
| `chore` | инфра, `.gitignore`, скрипты сборки без смены поведения |
| `refactor` | рефакторинг без изменения внешнего поведения |
| `test` | тесты |
| `ci` | CI/CD |

Примеры:

- `feat(chains): add Tron address validation`
- `docs(examples): document policy presets and docker flow`
- `chore: remove tracked plugin binary from repo`

Тело коммита и `BREAKING CHANGE:` в footer — по необходимости.

## Не используйте `git add -A`

Стадируйте **явно**, чтобы не утащить лишнее:

```bash
git status
git add path/to/file1 path/to/file2
git diff --cached
git commit -m "docs(examples): add quickstart for plugin and policies"
```

Для части дерева:

```bash
git add docs/ examples/README.md examples/policies/*.hcl
```

## Что обычно **не** коммитим

- Собранные бинарники плагина / `examples/plugin/*` (кроме `.gitkeep`)
- Локальные заметки: `IDEA.md`, `PLAN.md` (в `.gitignore`)
- `examples/payment-service/` — локальный пример; каталог в `.gitignore`, не правим в общих PR
- `examples/policies/setup.sh` — опциональный локальный скрипт; в репозитории шаблон — **`setup.sh.example`**

## Чеклист перед push

1. `git status` — нет неожиданных `M`/`??`
2. `git diff` — осознанные изменения
3. Один логический смысл на коммит (или явно разнесённые `feat` / `docs`)

## Запись демо-видео (asciinema / screen capture)

Краткий сценарий (совпадает с `examples/README.md`):

1. Из корня: `./examples/build-plugin.sh`
2. `cd examples && docker compose up -d`
3. `export VAULT_ADDR=…` и `VAULT_TOKEN=root`
4. `SHA=…` → `vault plugin register` → `vault secrets enable -plugin-name=…`
5. Политики: `vault policy write ops-admin examples/policies/ops-admin.hcl` (при необходимости остальные из `policies/README.md`)
6. Кошелёк и подпись: команды из раздела «First wallet» в `examples/README.md`

Опционально: скопировать `examples/policies/setup.sh.example` → `setup.sh`, выставить `PLUGIN_MOUNT`, выполнить для AppRole (только если нужно показать сервисный сценарий).
