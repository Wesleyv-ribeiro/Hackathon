#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"

echo "==> LabOrchestrator Linux build"
echo "Root:  $ROOT"
echo "Build: $BUILD"
echo

# Check dependencies
if ! command -v cmake >/dev/null 2>&1; then
    echo "ERROR: CMake not found."
    echo "Install it with your distribution's package manager."
    exit 1
fi

if ! command -v make >/dev/null 2>&1 && ! command -v ninja >/dev/null 2>&1; then
    echo "ERROR: No build tool found (make/ninja)."
    exit 1
fi

# Generate shared key if necessary
if [[ ! -f "$ROOT/keys/shared.key" ]]; then
    echo "==> Shared key not found. Generating..."
    "$ROOT/scripts/genkeys.sh"
fi

# Create build directory
mkdir -p "$BUILD"

cd "$BUILD"

# Detect stale CMake cache pointing somewhere else
if [[ -f "$BUILD/CMakeCache.txt" ]]; then
    CACHED_SOURCE="$(
        sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' \
            "$BUILD/CMakeCache.txt" | head -n 1
    )"

    if [[ -n "$CACHED_SOURCE" && "$CACHED_SOURCE" != "$ROOT" ]]; then
        echo "==> Existing build directory belongs to another source tree."
        echo "    Using build-local instead."

        BUILD="$ROOT/build-local"
        mkdir -p "$BUILD"
        cd "$BUILD"
    fi
fi

echo "==> Configuring CMake..."

cmake "$ROOT" \
    -DCMAKE_BUILD_TYPE=Release

echo
echo "==> Building..."

cmake --build . --config Release --parallel

echo
echo "==> Checking binaries..."

AGENT="$BUILD/agent/labagent"
ADMIN="$BUILD/admin/labadmin"

if [[ ! -x "$AGENT" ]]; then
    echo "ERROR: LabAgent binary not found:"
    echo "  $AGENT"
    exit 1
fi

if [[ ! -x "$ADMIN" ]]; then
    echo "ERROR: LabAdmin binary not found:"
    echo "  $ADMIN"
    exit 1
fi

echo
echo "Build successful."
echo
echo "Binaries:"
echo "  Agent: $AGENT"
echo "  Admin: $ADMIN"
