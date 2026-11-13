#!/usr/bin/env bash
# DecryptLab Ultimate - build script (Kali Linux / Debian)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BUILD_TYPE="${1:-Release}"
JOBS="$(nproc 2>/dev/null || echo 2)"

echo "[*] Configuring (CMake, ${BUILD_TYPE})..."
cmake -S . -B build -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
echo "[*] Building with ${JOBS} job(s)..."
cmake --build build -j "${JOBS}"
echo "[+] Done. Binary: build/bin/decryptlab"
