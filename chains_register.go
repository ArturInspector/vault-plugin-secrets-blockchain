// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package kv

// Import chain implementations so their init() runs and they register with chains.Registry.
import (
	_ "github.com/hashicorp/vault-plugin-secrets-kv/chains/bitcoin"
	_ "github.com/hashicorp/vault-plugin-secrets-kv/chains/ethereum"
	_ "github.com/hashicorp/vault-plugin-secrets-kv/chains/solana"
)
