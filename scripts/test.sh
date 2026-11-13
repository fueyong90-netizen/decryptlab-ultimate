#!/usr/bin/env bash
# DecryptLab Ultimate - run the test suite
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -d build ] || ./scripts/build.sh Release
echo "[*] Running unit tests..."
./build/bin/dlu_tests
echo "[*] Running CTest..."
ctest --test-dir build --output-on-failure
echo "[+] Tests done."
