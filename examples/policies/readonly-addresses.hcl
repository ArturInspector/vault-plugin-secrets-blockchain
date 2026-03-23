# readonly-addresses — auditors, dashboards, support: see addresses and lists, no signing.
#
# vault policy write readonly-addresses examples/policies/readonly-addresses.hcl

path "blockchain/chains/*/wallets/" {
  capabilities = ["list"]
}

path "blockchain/chains/*/wallets/*" {
  capabilities = ["read"]
}
