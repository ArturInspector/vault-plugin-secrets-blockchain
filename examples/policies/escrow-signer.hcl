# escrow-signer — narrow signing only for wallets whose names start with escrow- (release/refund flows).
# Pair with readonly-addresses for CI that checks balances off-chain.
#
# vault policy write escrow-signer examples/policies/escrow-signer.hcl

path "blockchain/chains/*/wallets/" {
  capabilities = ["list"]
}

path "blockchain/chains/*/wallets/*" {
  capabilities = ["read"]
}

path "blockchain/chains/*/wallets/escrow-*/sign" {
  capabilities = ["create", "update"]
}

path "blockchain/chains/*/wallets/escrow-*/sign_raw" {
  capabilities = ["create", "update"]
}
