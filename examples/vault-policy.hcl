# vault-policy.hcl — пример политики для escrow-service.
#
# ВАЖНО: "blockchain" — это путь монтирования плагина (vault secrets enable -path=blockchain).
# Все пути политик должны начинаться с этого префикса.
#
# Полные примеры политик по ролям — см. policies/ директорию.

# Листать кошельки по цепи
path "blockchain/chains/*/wallets/" {
  capabilities = ["list"]
}

# Читать адрес кошелька (публичная информация, приватный ключ не возвращается)
path "blockchain/chains/*/wallets/*" {
  capabilities = ["read"]
}

# Подписывать транзакции escrow-кошельков
path "blockchain/chains/*/wallets/escrow-*/sign" {
  capabilities = ["create", "update"]
}

# Подписывать сырые хэши (EIP-712, permit, off-chain messages)
path "blockchain/chains/*/wallets/escrow-*/sign_raw" {
  capabilities = ["create", "update"]
}
