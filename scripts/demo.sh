#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AGENT="$ROOT/build/agent/labagent"
ADMIN="$ROOT/build/admin/labadmin"
POLICY="$ROOT/policies/default.json"

if [[ ! -x "$AGENT" ]]; then
    echo "LabAgent not found."
    echo
    echo "Run first:"
    echo "  ./scripts/build.sh"
    exit 1
fi

if [[ ! -x "$ADMIN" ]]; then
    echo "LabAdmin not found."
    echo
    echo "Run first:"
    echo "  ./scripts/build.sh"
    exit 1
fi

echo "=== Demo LabOrchestrator ==="
echo
echo "1. Start the agent in another terminal:"
echo
echo "   $AGENT --key keys/shared.key"
echo
echo "2. Discover agents:"
echo
echo "   $ADMIN discover"
echo
echo "3. Send policy:"
echo
echo "   $ADMIN push <AGENT_ID> $POLICY"
echo
echo "4. Switch profile:"
echo
echo "   $ADMIN switch <AGENT_ID> Programacao"
echo
echo "5. Trigger reset:"
echo
echo "   $ADMIN reset <AGENT_ID>"
echo
