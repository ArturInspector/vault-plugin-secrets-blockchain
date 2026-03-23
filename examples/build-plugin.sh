#!/usr/bin/env bash
# Build the plugin binary into examples/plugin/ for docker-compose dev mode.
# Usage: from repo root —  ./examples/build-plugin.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/examples/plugin/vault-plugin-secrets-blockchain"
mkdir -p "$(dirname "$OUT")"
echo "Building -> ${OUT}"
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$OUT" ./cmd/vault-plugin-secrets-blockchain)
ls -la "$OUT"
SHA=$(sha256sum "$OUT" | awk '{print $1}')
echo "SHA256: ${SHA}"
echo "Register with: vault plugin register -sha256=${SHA} secret vault-plugin-secrets-blockchain"
