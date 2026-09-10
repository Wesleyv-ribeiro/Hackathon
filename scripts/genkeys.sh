#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KEY_DIR="$ROOT/keys"
KEY_PATH="$KEY_DIR/shared.key"

mkdir -p "$KEY_DIR"

if [[ -f "$KEY_PATH" ]]; then
    echo "Shared key already exists:"
    echo "  $KEY_PATH"
    exit 0
fi

echo "==> Generating 256-bit HMAC key..."

umask 077
dd if=/dev/urandom of="$KEY_PATH" bs=32 count=1 status=none

chmod 600 "$KEY_PATH"

echo "HMAC key generated:"
echo "  $KEY_PATH"
echo
echo "Distribute this file to all agents and the administrator."
