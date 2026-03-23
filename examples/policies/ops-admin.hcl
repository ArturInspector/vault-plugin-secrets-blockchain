# ops-admin — full control over wallets, signing, HD, and freeze (platform / on-call).
# Replace mount prefix "blockchain" if your secrets engine is mounted elsewhere.
#
# vault policy write ops-admin examples/policies/ops-admin.hcl

# List wallets per chain
path "blockchain/chains/*/wallets/" {
  capabilities = ["list"]
}

# Create / read / delete wallet; tier and body fields via POST
path "blockchain/chains/*/wallets/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "blockchain/chains/*/wallets/*/import" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/*/rotate" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/*/sign" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/*/sign_raw" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/*/freeze" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/*/unfreeze" {
  capabilities = ["create", "update"]
}

# HD master (global seed, derive, recover)
path "blockchain/hd" {
  capabilities = ["create", "read", "update"]
}

path "blockchain/hd/recover" {
  capabilities = ["create", "update"]
}

path "blockchain/hd/derive/*" {
  capabilities = ["create", "update"]
}
