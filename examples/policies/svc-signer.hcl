# svc-signer — backend service: sign only for named wallets, read addresses. No create/delete/import/HD.
# Tighten wallet names in production (e.g. payment-prod-* only).
#
# vault policy write svc-signer examples/policies/svc-signer.hcl

path "blockchain/chains/*/wallets/" {
  capabilities = ["list"]
}

# Read published address only (private key never returned by API)
path "blockchain/chains/*/wallets/*" {
  capabilities = ["read"]
}

# Signing for operational wallets (adjust prefix to your naming convention)
path "blockchain/chains/*/wallets/payment-*/sign" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/payment-*/sign_raw" {
  capabilities = ["create", "update"]
}

# Optional: escrow-only variant — uncomment and remove payment-* blocks if you use escrow-* names only
# path "blockchain/chains/*/wallets/escrow-*/sign" {
#   capabilities = ["create", "update"]
# }
# path "blockchain/chains/*/wallets/escrow-*/sign_raw" {
#   capabilities = ["create", "update"]
# }
