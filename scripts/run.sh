#!/usr/bin/env bash
# DecryptLab Ultimate - launcher
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BIN="build/bin/decryptlab"
[ -x "$BIN" ] || ./scripts/build.sh Release
exec "$BIN" "$@"
